"""Informes de Nessus y OpenVAS: importarlos, resumirlos, convertirlos en un plan de pruebas de opsdeck
y volver a verificar automáticamente lo que se puede comprobar desde la red (TLS, SSH, SMB, RDP,
servicios expuestos, marcas de tiempo, web).

Sirve para el ciclo habitual: llega el informe del escáner → se reparte el trabajo → se corrige →
«¿sigue saliendo?» sin esperar al siguiente escaneo completo."""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from pathlib import Path

from ..core import audit, informes, recomendacion, results, scope
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.informes import Item

SEVS = ("CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO")
MIN_SEV = [("BAJO", "Baja o superior"), ("MEDIO", "Media o superior"), ("ALTO", "Alta o superior"),
           ("CRÍTICO", "Solo críticas"), ("INFO", "Todo, también informativas")]


def _imports() -> list[Path]:
    return [s for s in results.sessions("informes", 50) if (s / "hallazgos.json").exists()]


def _label(d: Path) -> str:
    n = d.name
    return f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}  {n[16:]}"


def _pick(ctx: Context, v: dict) -> tuple[list[Item], Path | None]:
    imps = _imports()
    if not imps:
        ctx.out.error("No hay informes importados: usa antes «Importar informe».")
        return [], None
    n = str(v.get("informe") or "1").strip()
    if not n.isdigit() or not 1 <= int(n) <= len(imps):
        ctx.out.error(f"Número de informe no válido (1-{len(imps)}). Míralos en «Informes importados».")
        return [], None
    d = imps[int(n) - 1]
    ctx.out.info(f"Informe: {_label(d)}")
    return informes.read(d / "hallazgos.json"), d


def _filter(items: list[Item], minsev: str) -> list[Item]:
    lim = SEVS.index(minsev) if minsev in SEVS else 3
    return [i for i in items if SEVS.index(i.severidad) <= lim]


def importar(ctx: Context, v: dict) -> bool:
    path = Path((v.get("fichero") or "").strip()).expanduser()
    items, fmt = informes.load(path)
    if not items:
        ctx.out.error(fmt)
        return False
    d = results.new_dir("informes", f"{path.stem[:40]}")
    informes.save(items, d / "hallazgos.json")
    results.write(d / "origen.txt", f"{path}\nformato={fmt}\n")
    ctx.out.ok(f"Importados {len(items)} resultados ({fmt}) de {len({i.host for i in items})} equipos.")
    if fmt == "pdf":
        ctx.out.warn("Leído desde PDF: es lo menos fiable (los puertos pueden faltar en el formato «por equipo»). "
                     "Si puedes, exporta el informe en .nessus, XML o CSV.")
    audit.record("informe_importar", str(path), "OK", f"{fmt} items={len(items)}")
    return _summary(ctx, items, v.get("severidad") or "BAJO")


def _summary(ctx: Context, items: list[Item], minsev: str) -> bool:
    sev = Counter(i.severidad for i in items)
    ctx.out.title("Por severidad: " + "  ".join(f"{s}={sev[s]}" for s in SEVS if sev.get(s)))
    sel = _filter(items, minsev)
    by_name: dict = defaultdict(set)
    sev_name: dict = {}
    for i in sel:
        by_name[i.nombre].add(i.host)
        sev_name[i.nombre] = min(sev_name.get(i.nombre, "INFO"), i.severidad, key=SEVS.index)
    rows = sorted(([sev_name[n], str(len(h)), n[:70], informes.donde(informes.classify(
        next(i for i in sel if i.nombre == n))[0])[0]] for n, h in by_name.items()),
        key=lambda r: (SEVS.index(r[0]), -int(r[1])))
    ctx.out.title(f"Hallazgos distintos ({len(rows)}) — cuántos equipos y con qué se comprueba en opsdeck")
    ctx.out.table(["Severidad", "Equipos", "Hallazgo", "En opsdeck"], rows[:80])
    hosts = Counter(i.host for i in sel if i.severidad in ("CRÍTICO", "ALTO"))
    if hosts:
        ctx.out.title("Equipos con más hallazgos críticos/altos")
        ctx.out.table(["Equipo", "Crít.+altos"], [[h, str(n)] for h, n in hosts.most_common(10)])
    return True


def ver(ctx: Context, v: dict) -> bool:
    imps = _imports()
    if not v.get("informe"):
        if not imps:
            ctx.out.info("Todavía no hay informes importados.")
            return True
        ctx.out.table(["Nº", "Fecha y nombre", "Resultados"],
                      [[str(i + 1), _label(d), str(len(informes.read(d / "hallazgos.json")))] for i, d in enumerate(imps[:20])])
        ctx.out.info("Indica el número para ver su resumen.")
        return True
    items, d = _pick(ctx, v)
    return bool(d) and _summary(ctx, items, v.get("severidad") or "BAJO")


def plan(ctx: Context, v: dict) -> bool:
    items, d = _pick(ctx, v)
    if not d:
        return False
    sel = _filter(items, v.get("severidad") or "BAJO")
    groups: dict = defaultdict(list)
    for i in sel:
        groups[informes.classify(i)[0]].append(i)
    pd = d / "plan"
    pd.mkdir(exist_ok=True)
    rows, lines = [], ["# Plan de verificación", ""]
    for check, its in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        where, cli = informes.donde(check)
        hosts = sorted({i.host for i in its}, key=_ipkey)
        eps = sorted({i.objetivo for i in its}, key=_ipkey)
        f = pd / f"objetivos_{check.replace(':', '_')}.txt"
        results.write(f, "\n".join(eps if check in ("tls", "ssh") else hosts) + "\n")
        names = Counter(i.nombre for i in its)
        rows.append([where, str(len(hosts)), str(len(its)), "; ".join(n[:40] for n, _ in names.most_common(2))])
        lines += [f"## {where}", "", f"Equipos: {len(hosts)} · resultados: {len(its)}", ""]
        lines += [f"- {n} ({c})" for n, c in names.most_common()]
        if cli:
            lines += ["", f"    opsdeck {cli} --objetivo {f}", ""]
        else:
            lines += [""]
    ctx.out.table(["Comprobación en opsdeck", "Equipos", "Resultados", "Ejemplos"], rows)
    results.write(pd / "plan.md", "\n".join(lines) + "\n")
    ctx.out.info(f"Plan y listas de objetivos en {pd}: cada lista se puede usar como «objetivo» de su módulo.")
    ctx.out.info("Lo comprobable desde la red se puede re-verificar de una vez con «Volver a verificar».")
    return True


def _ipkey(s: str):
    host = s.split(":")[0]
    return tuple(int(x) if x.isdigit() else 0 for x in host.split(".")) + (s,)


def _port(obj: str):
    m = re.match(r"^[^:]+:(\d+)", obj)
    return int(m.group(1)) if m else None


def verificar(ctx: Context, v: dict) -> bool:
    items, d = _pick(ctx, v)
    if not d:
        return False
    sel = _filter(items, v.get("severidad") or "BAJO")
    groups: dict = defaultdict(list)
    for i in sel:
        groups[informes.classify(i)[0]].append(i)
    auto = [c for c in groups if c in ("tls", "ssh", "smb", "rdp", "icmp", "tcp", "web", "web_ficheros")
            or c.startswith("exposicion:")]
    if not auto:
        ctx.out.info("Ninguno de los hallazgos seleccionados se puede re-verificar automáticamente desde la red.")
        return True
    hosts_all = sorted({i.host for c in auto for i in groups[c]}, key=_ipkey)
    if not scope.gate(ctx, " ".join(hosts_all), v, "informe_verificar"):
        return False
    vd = results.new_dir("informes", f"verificacion_{d.name[16:][:30]}")
    findings: list[recomendacion.Finding] = []
    checked: set = set()                         # (host, puerto) que respondieron
    web_text: dict = defaultdict(list)           # host:puerto -> textos de hallazgos web

    if "tls" in groups:
        from .tls import run_checks as tls_run
        g: dict = defaultdict(set)
        for i in groups["tls"]:
            if i.puerto:
                g[i.host].add(i.puerto)
            else:
                g[i.host]
        ctx.out.title(f"TLS: {len(g)} equipos")
        f, rows = tls_run(ctx, dict(g), {"sslscan": True}, vd)
        findings += f
        checked |= {(r[0].split(":")[0], int(r[0].split(":")[1])) for r in rows}
    if "ssh" in groups:
        from .ssh import run_checks as ssh_run
        g = defaultdict(set)
        for i in groups["ssh"]:
            if i.puerto:
                g[i.host].add(i.puerto)
            else:
                g[i.host]
        ctx.out.title(f"SSH: {len(g)} equipos")
        f, rows = ssh_run(ctx, dict(g), {"ssh_audit": False}, vd)
        findings += f
        checked |= {(r[0].split(":")[0], int(r[0].split(":")[1])) for r in rows}
    svc = sorted({c.split(":", 1)[1] for c in auto if c.startswith("exposicion:")}
                 | ({"smb"} if "smb" in groups else set()) | ({"rdp"} if "rdp" in groups else set()))
    if svc:
        from .exposicion import BY_ID, run_checks as exp_run
        hosts = sorted({i.host for c in auto if c.startswith("exposicion:") or c in ("smb", "rdp") for i in groups[c]},
                       key=_ipkey)
        ctx.out.title(f"Servicios ({', '.join(svc)}): {len(hosts)} equipos")
        f, rows, _ = exp_run(ctx, hosts, {"udp": any(BY_ID[s].udp for s in svc if s in BY_ID)}, vd,
                             [BY_ID[s] for s in svc if s in BY_ID])
        findings += f
        for r in rows:
            m = re.match(r"^([^:]+):(\d+)/", r[0])
            if m:
                checked.add((m.group(1), int(m.group(2))))
    if "icmp" in groups or "tcp" in groups:
        from .exposicion import leak_checks
        hosts = sorted({i.host for c in ("icmp", "tcp") for i in groups.get(c, [])}, key=_ipkey)
        ctx.out.title(f"Marcas de tiempo ICMP/TCP: {len(hosts)} equipos")
        f, _ = leak_checks(ctx, hosts, {"icmp": "icmp" in groups, "tcp": "tcp" in groups}, vd)
        findings += f
    for c in ("web", "web_ficheros"):
        if c not in groups:
            continue
        from .web import check_url, request, sensitive_files
        eps = sorted({(i.host, i.puerto) for i in groups[c] if i.puerto})
        ctx.out.title(f"Web: {len(eps)} servicios")
        for host, port in eps:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}"
                if request(url, limit=1000, timeout=5).get("error"):
                    continue
                r = check_url(url, deep=True) if c == "web" else {"http": {}, "hallazgos": [
                    (sv, f"{w}: /{pth}") for pth, _, sv, w in sensitive_files(url)]}
                checked.add((host, port))
                web_text[f"{host}:{port}:{c}"] += [t for _, t in r["hallazgos"]]
                break

    by_host_tipo: dict = defaultdict(set)
    for f in findings:
        h = f.objetivo.split(":")[0]
        by_host_tipo[(h, f.tipo)].add(_port(f.objetivo))
    rows, out_csv = [], []
    state_count: Counter = Counter()
    for i in sel:
        check, tipos, txt = informes.classify(i)
        if check not in auto:
            state = "PENDIENTE (manual/otra herramienta)"
        elif check in ("web", "web_ficheros"):
            texts = web_text.get(f"{i.host}:{i.puerto}:{check}")
            if texts is None:
                state = "NO ACCESIBLE"
            else:
                state = "SIGUE" if any(re.search(txt, t, re.I) for t in texts) else "NO REPRODUCIDO"
        else:
            ports = set().union(*[by_host_tipo.get((i.host, t), set()) for t in tipos]) if tipos else set()
            hit = bool(ports) and (i.puerto is None or i.puerto in ports or None in ports)
            if hit:
                state = "SIGUE"
            elif i.puerto and check in ("tls", "ssh") and (i.host, i.puerto) not in checked:
                state = "NO ACCESIBLE"
            else:
                state = "NO REPRODUCIDO"
        state_count[state] += 1
        rows.append([state, i.severidad, i.objetivo, i.nombre[:60]])
        out_csv.append([state, i.severidad, i.host, i.puerto or "", i.nombre, informes.donde(check)[0]])
    order = {"SIGUE": 0, "NO ACCESIBLE": 1, "NO REPRODUCIDO": 2}
    rows.sort(key=lambda r: (order.get(r[0], 3), SEVS.index(r[1]), _ipkey(r[2])))
    ctx.out.title("Resultado de la verificación: " + "  ·  ".join(f"{k}: {n}" for k, n in state_count.most_common()))
    ctx.out.table(["Estado", "Severidad", "Dónde", "Hallazgo del informe"],
                  [r for r in rows if not r[0].startswith("PENDIENTE")][:150])
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["estado", "severidad", "equipo", "puerto", "hallazgo", "comprobacion"])
    w.writerows(out_csv)
    results.write(vd / "verificacion.csv", buf.getvalue())
    results.write(vd / "hallazgos_opsdeck.json", recomendacion.to_json(findings))
    ctx.out.info("NO REPRODUCIDO = opsdeck no lo ve ahora (probablemente corregido; confírmalo en el siguiente "
                 "escaneo del escáner). NO ACCESIBLE = el servicio no respondió. PENDIENTE = versiones/CVE y "
                 f"fin de soporte: usa nuclei dirigido o revisa a mano. CSV: {vd / 'verificacion.csv'}")
    audit.record("informe_verificar", d.name, "OK", " ".join(f"{k}={n}" for k, n in state_count.items()))
    return True


class Informes(Module):
    full = True
    id = "informes"
    name = "Informes Nessus / OpenVAS"
    category = "Ciberseguridad"
    summary = "Importar informes de escáneres, plan de pruebas y re-verificación tras corregir"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    optional = [cmd("pdftotext", debian="poppler-utils", rhel="poppler-utils", suse="poppler-tools", arch="poppler",
                    label="pdftotext (leer informes en PDF)")]
    help = """\
# Informes Nessus / OpenVAS

Convierte el informe de un escáner de vulnerabilidades en trabajo concreto en opsdeck.

1. **Importar informe**: `.nessus`, XML de OpenVAS/Greenbone, CSV de cualquiera de los dos o, como
   último recurso, el **PDF** (Nessus «por equipo» o «por plugin», OpenVAS «resultados por equipo»).
   Muestra el resumen por severidad, cada hallazgo distinto con cuántos equipos lo tienen y **con
   qué módulo de opsdeck se comprueba**.
2. **Plan de verificación**: agrupa los hallazgos por comprobación (TLS, SSH, SMB, RDP, marcas de
   tiempo, servicios, web, nuclei, manual) y deja una **lista de objetivos** por grupo que se puede
   usar directamente como objetivo de cada módulo, más un `plan.md` con las órdenes.
3. **Volver a verificar**: relanza automáticamente las comprobaciones de red de los hallazgos del
   informe y marca cada uno como **SIGUE**, **NO REPRODUCIDO** (probablemente corregido) o **NO
   ACCESIBLE**. Las vulnerabilidades por versión (CVE) y el fin de soporte quedan como pendientes
   (para eso, nuclei dirigido y los parches).

> Las IP del informe pasan por la barandilla de alcance igual que cualquier otro objetivo.
"""

    def actions(self):
        n = Param("informe", "Informe importado (nº, 1 = el último)", "int", 1)
        sev = Param("severidad", "Desde severidad", "choice", "BAJO", choices=MIN_SEV)
        return [
            Action("importar", "Importar informe", importar, params=[
                Param("fichero", "Fichero del informe", help=".nessus, .xml, .csv o .pdf"), sev]),
            Action("ver", "Informes importados", ver, params=[
                Param("informe", "Nº (vacío = listar)", required=False), sev]),
            Action("plan", "Plan de verificación", plan, params=[n, sev]),
            Action("verificar", "Volver a verificar", verificar, params=[n, sev, scope.ok_param()],
                   confirm="Se relanzarán comprobaciones activas (nmap/TLS/SSH/servicios/web) contra los equipos "
                           "del informe. ¿Tienes autorización?"),
        ]
