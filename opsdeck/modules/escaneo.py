"""Escaneo de red con nmap: descubrir equipos, perfiles de escaneo, resumen compacto y comparar escaneos.

Cada escaneo se guarda (XML, texto y grepable) en /var/lib/opsdeck/resultados/escaneo/ y se resume
leyendo el XML. Solo contra sistemas propios o con autorización por escrito."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import ipaddress

from ..core import audit, config, edition, feeds, nmapxml, recomendacion, results, scope, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream

TARGET_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._:/-]*[A-Za-z0-9])?$")
VULN_SCRIPTS = "(vuln or vulners) and not (http-slowloris-check or http-dombased-xss or http-stored-xss or http-csrf)"
PROFILES = {
    "rapido": ("Rápido: 100 puertos más comunes", ["-sS", "-T4", "-F", "--open"]),
    "estandar": ("Estándar: 1000 puertos + versiones", ["-sS", "-sV", "-T4", "--top-ports", "1000", "--open"]),
    "completo": ("Completo: los 65535 puertos, después versiones, scripts y SO", None),
    "vulnerabilidades": ("Vulnerabilidades: 1000 puertos + scripts NSE y CVE (intrusivo)",
                         ["-sS", "-sV", "-T4", "--top-ports", "1000", "--open", "--script", VULN_SCRIPTS,
                          "--script-args", "mincvss=7.0"]),
    "udp": ("UDP: 100 puertos más comunes", ["-sU", "-sV", "--version-intensity", "0", "-T4", "--top-ports", "100", "--open"]),
    "sigiloso": ("Sigiloso: lento y fragmentado (evasión de IDS)",
                 ["-sS", "-Pn", "-n", "-T2", "--top-ports", "100", "-f", "--randomize-hosts", "--max-retries", "1"]),
}
LIGHT_PROFILES = ("rapido", "estandar")
FORBIDDEN = ("-o", "-iL", "--script-updatedb", "--datadir", "--resume", "--stylesheet")


def _targets(ctx, text: str) -> list[str]:
    items = text.split()
    if not items:
        ctx.out.error("Indica al menos un objetivo")
        return []
    if len(items) == 1 and Path(items[0]).is_file():
        return ["-iL", items[0]]
    for t in items:
        if not TARGET_RE.match(t):
            ctx.out.error(f"Objetivo no válido: '{t}'")
            return []
    return items


def _exclude(text: str) -> list[str]:
    text = (text or "").replace(" ", "")
    return ["--exclude", text] if text and re.match(r"^[A-Za-z0-9.,/:-]+$", text) else []


def _run(ctx, label: str, args: list[str], targets: list[str], exclude: str, d: Path, name: str) -> tuple[int, Path]:
    out = d / name
    cmd_line = ["nmap", *args, *_exclude(exclude), "-oA", str(out), "--stats-every", "30s", *targets]
    ctx.out.info("$ " + " ".join(shlex.quote(a) for a in cmd_line))
    rc, _ = stream(ctx, cmd_line, accion=f"nmap_{label}", objetivo=" ".join(targets), detalle=" ".join(args),
                   keep=60)
    return rc, out.with_suffix(".xml")


def summary(ctx: Context, scan: nmapxml.Scan, maxp: int = 12) -> None:
    up = scan.up()
    with_ports = [h for h in up if h.open_ports()]
    services: dict[str, int] = {}
    for h in with_ports:
        for p in h.open_ports():
            services[p.service or "?"] = services.get(p.service or "?", 0) + 1
    ctx.out.title(f"{len(up)} equipos activos · {len(with_ports)} con puertos abiertos · "
                  f"{sum(len(h.open_ports()) for h in with_ports)} puertos")
    if services:
        ctx.out.line("  Servicios: " + "  ".join(f"{k}({v})" for k, v in sorted(services.items(), key=lambda x: -x[1])[:10]))
    rows = []
    for h in sorted(up, key=lambda h: tuple(int(x) if x.isdigit() else 0 for x in h.ip.split("."))):
        ports = h.open_ports()
        txt = " ".join(p.label for p in ports[:maxp]) + (f" (+{len(ports) - maxp})" if len(ports) > maxp else "")
        flags = []
        vul = h.vulnerable()
        if vul:
            flags.append(f"VULN:{len(vul)}")
        cv = h.max_cvss()
        if cv >= 7:
            flags.append(f"CVSS {cv}")
        rows.append([h.ip, (h.name or h.mac_vendor)[:24], txt or "-", " ".join(flags)])
    ctx.out.table(["Equipo", "Nombre / fabricante", "Puertos abiertos", "Avisos"], rows)
    found = [(h.ip, sid, title) for h in up for sid, title in h.vulnerable()]
    if found:
        ctx.out.title("Hallazgos marcados VULNERABLE por nmap")
        for ip, sid, title in found:
            ctx.out.line(f"  {ip}  {sid}: {title[:90]}")
    if any(h.max_cvss() for h in up):
        ctx.out.info("CVSS sale del número de versión (vulners): no ve los parches de la distribución. Verifica antes de actuar.")
    recomendacion.render(ctx, recomendacion.from_scan(scan))


def descubrir(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "descubrir"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    d = results.new_dir("escaneo", f"descubrimiento_{v['objetivo']}")
    rc, xml = _run(ctx, "descubrimiento", ["-sn", "-PE", "-PP", "-PS21,22,80,443,445,3389,8080", "-PA80,443",
                                           "-PU53,161"], t, v.get("excluir", ""), d, "descubrimiento")
    scan = nmapxml.parse(xml)
    up = scan.up()
    results.write(d / "hosts_activos.txt", "\n".join(h.ip for h in up) + "\n")
    ctx.out.title(f"{len(up)} equipos activos")
    ctx.out.table(["IP", "Nombre", "Fabricante (MAC)"], [[h.ip, h.name, h.mac_vendor] for h in up])
    ctx.out.info(f"Lista guardada en {d / 'hosts_activos.txt'}: úsala como objetivo de un escaneo.")
    return rc == 0


def escanear(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "escanear"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    prof = v["perfil"]
    if prof not in LIGHT_PROFILES and not edition.allowed_full()[0]:
        ctx.out.error(f"El perfil '{prof}' es de la edición completa. {edition.allowed_full()[1]}")
        return False
    if prof == "vulnerabilidades":
        feeds.warn_if_stale(ctx)
    d = results.new_dir("escaneo", f"{prof}_{v['objetivo'].replace('/', '_')}")
    if prof == "completo":
        rc, xml = _run(ctx, "completo_puertos", ["-sS", "-p-", "-T4", "--min-rate", "1000", "--open", "-n"], t,
                       v.get("excluir", ""), d, "1_puertos")
        first = nmapxml.parse(xml)
        ports = sorted({p.port for h in first.up() for p in h.open_ports()})
        hosts = [h.ip for h in first.up() if h.open_ports()]
        if rc != 0 or not ports:
            if not ports:
                ctx.out.warn("No se encontraron puertos abiertos.")
            summary(ctx, first)
            return rc == 0
        ctx.out.info(f"Puertos abiertos: {','.join(map(str, ports))}. Analizando servicios en {len(hosts)} equipos...")
        rc, xml = _run(ctx, "completo_servicios", ["-sS", "-sV", "-sC", "-O", "-T4", "-p", ",".join(map(str, ports))],
                       hosts, "", d, "2_servicios")
    else:
        rc, xml = _run(ctx, prof, PROFILES[prof][1], t, v.get("excluir", ""), d, prof)
    summary(ctx, nmapxml.parse(xml))
    ctx.out.info(f"Resultados completos en {d}")
    return rc == 0


def personalizado(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "personalizado"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    try:
        flags = shlex.split(v["opciones"])
    except ValueError as e:
        ctx.out.error(f"Opciones mal escritas: {e}")
        return False
    bad = [f for f in flags if f.startswith(FORBIDDEN)]
    if bad:
        ctx.out.error(f"No se permiten estas opciones (la herramienta gestiona la salida): {' '.join(bad)}")
        return False
    d = results.new_dir("escaneo", f"personalizado_{v['objetivo'].replace('/', '_')}")
    rc, xml = _run(ctx, "personalizado", flags, t, v.get("excluir", ""), d, "personalizado")
    summary(ctx, nmapxml.parse(xml))
    return rc == 0


def escaneos() -> list[Path]:
    out = []
    for s in results.sessions("escaneo", 50):
        xmls = sorted(s.glob("*.xml"))
        if xmls:
            out.append(xmls[-1])
    return out


def _label(p: Path) -> str:
    n = p.parent.name
    return f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}  {n[16:]}"


def ver(ctx: Context, v: dict) -> bool:
    scans = escaneos()
    if not scans:
        ctx.out.info("Todavía no hay escaneos guardados.")
        return True
    which = v.get("escaneo") or ""
    if not which:
        ctx.out.title("Escaneos guardados (el más reciente primero)")
        ctx.out.table(["Nº", "Fecha y objetivo"], [[str(i + 1), _label(p)] for i, p in enumerate(scans[:20])])
        ctx.out.info("Repite indicando el número para ver su resumen.")
        return True
    if not which.isdigit() or not 1 <= int(which) <= len(scans):
        ctx.out.error("Número de escaneo no válido")
        return False
    p = scans[int(which) - 1]
    ctx.out.info(_label(p) + f"   ({p.parent})")
    summary(ctx, nmapxml.parse(p))
    return True


def comparar(ctx: Context, v: dict) -> bool:
    scans = escaneos()
    try:
        a, b = int(v.get("anterior") or 2), int(v.get("reciente") or 1)
        old, new = scans[a - 1], scans[b - 1]
    except (ValueError, IndexError):
        ctx.out.error("Hacen falta dos escaneos guardados (míralos en 'Ver escaneos guardados').")
        return False
    ctx.out.info(f"Antes:   {_label(old)}\nDespués: {_label(new)}")
    c = nmapxml.diff(nmapxml.parse(old), nmapxml.parse(new))
    nothing = True
    for key, title in (("hosts_nuevos", "Equipos nuevos"), ("hosts_desaparecidos", "Equipos que ya no responden")):
        if c[key]:
            nothing = False
            ctx.out.title(f"{title} ({len(c[key])})")
            ctx.out.line("  " + "  ".join(c[key]))
    for key, title in (("puertos_abiertos", "Puertos abiertos nuevos"), ("puertos_cerrados", "Puertos que se han cerrado")):
        if c[key]:
            nothing = False
            ctx.out.title(f"{title} ({len(c[key])})")
            ctx.out.table(["Equipo", "Puerto"], [list(x) for x in c[key]])
    if c["versiones"]:
        nothing = False
        ctx.out.title("Cambios de versión de servicios")
        ctx.out.table(["Equipo", "Puerto", "Antes", "Ahora"], [list(x) for x in c["versiones"]])
    if nothing:
        ctx.out.ok("Sin cambios entre los dos escaneos.")
    else:
        ctx.out.info("Un equipo o puerto nuevo que nadie esperaba merece una revisión.")
    return True


def _save_redes(nets: list[str]) -> None:
    config.set_value("red", "redes_autorizadas", ", ".join(nets))


def alcance(ctx: Context, v: dict) -> bool:
    accion = (v.get("accion") or "ver").strip().lower()
    red = (v.get("red") or "").strip()
    if accion in ("añadir", "anadir", "quitar"):
        if not system.is_root():
            ctx.out.error("Cambiar el alcance modifica la configuración y necesita root. Abre la herramienta con sudo.")
            return False
        try:
            net = str(ipaddress.ip_network(red, strict=False))
        except ValueError:
            ctx.out.error(f"Red no válida; usa notación CIDR, p. ej. 10.0.0.0/24 (recibido: {red!r})")
            return False
        actuales = [str(n) for n in scope.configured_networks()]
        if accion in ("añadir", "anadir"):
            if net in actuales:
                ctx.out.info(f"{net} ya estaba autorizada.")
            else:
                _save_redes(actuales + [net])
                audit.record("alcance_añadir", net, "OK")
                ctx.out.ok(f"Autorizada la red {net}.")
        else:
            if net not in actuales:
                ctx.out.info(f"{net} no estaba en la lista de redes autorizadas.")
            else:
                actuales.remove(net)
                _save_redes(actuales)
                audit.record("alcance_quitar", net, "OK")
                ctx.out.ok(f"Retirada la red {net}.")
    ctx.out.title("Alcance autorizado")
    conf = [str(n) for n in scope.configured_networks()]
    solo = config.settings().getboolean("red", "solo_configuradas", fallback=False)
    ctx.out.line("  Redes configuradas: " + (", ".join(conf) or "ninguna"))
    if solo:
        ctx.out.line("  solo_configuradas = true: las subredes locales NO se tienen en cuenta.")
    else:
        loc = [str(n) for n in scope.local_networks()]
        ctx.out.line("  Subredes locales (automáticas): " + (", ".join(loc) or "ninguna"))
    ctx.out.info("Cualquier objetivo fuera de este alcance se bloquea salvo que se autorice "
                 "manualmente, y esa autorización queda en el registro de auditoría.")
    return True


def _subnets() -> list[str]:
    out = []
    if system.has_cmd("ip"):
        for line in system.run(["ip", "-4", "-o", "route", "show", "scope", "link"], c_locale=True).out.splitlines():
            if line.split() and "/" in line.split()[0]:
                out.append(line.split()[0])
    out += [str(p) for s in results.sessions("escaneo", 10) for p in s.glob("hosts_activos.txt")]
    return out


def _confirm(v: dict) -> str:
    if v.get("perfil") == "vulnerabilidades":
        return ("El perfil de vulnerabilidades lanza pruebas activas que pueden afectar a servicios frágiles. "
                f"Objetivo: {v.get('objetivo')}. ¿Tienes autorización y quieres continuar?")
    return ""


class Escaneo(Module):
    id = "escaneo"
    name = "Escaneo de red (nmap)"
    category = "Ciberseguridad"
    summary = "Descubrir equipos, escanear puertos y servicios, ver y comparar escaneos"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    help = """\
# Escaneo de red (nmap)

> Úsalo solo contra sistemas propios o con **autorización por escrito**.

**Alcance:** los escaneos se confinan a las redes a las que este equipo está conectado y a las que
autorices en **Alcance autorizado**. Un objetivo fuera de ahí se bloquea; para seguir hay que marcar
«Autorizo trabajar fuera del alcance», y queda registrado. Es una barandilla contra errores de alcance,
no un muro frente a quien tenga root.

**Flujo recomendado:**
1. **Descubrir equipos** de una red (p. ej. `192.168.0.0/24`): rápido, solo dice quién está encendido
   y guarda la lista en `hosts_activos.txt`.
2. **Escanear** esa lista (escribe la ruta del fichero como objetivo) con un perfil
   (en la edición ligera solo *Rápido* y *Estándar*):

| Perfil | Para qué |
|---|---|
| Rápido | Primera idea en segundos |
| Estándar | Puertos habituales y versión de cada servicio |
| Completo | Todos los puertos; después versiones, scripts y sistema operativo solo de lo abierto |
| Vulnerabilidades | Scripts NSE de vulnerabilidades y CVE conocidos (intrusivo, pide confirmación) |
| UDP | DNS, SNMP, NTP... (lento por naturaleza) |
| Sigiloso | Lento y fragmentado, para probar si un IDS lo detecta |

3. **Ver escaneos guardados**: resumen compacto, una línea por equipo.
4. **Comparar escaneos**: equipos y puertos nuevos o desaparecidos y cambios de versión.
   Hazlo periódicamente para detectar servicios que aparecen sin que nadie los haya pedido.

**Objetivos** válidos: IP, nombre, rango (`10.0.0.1-50`), red (`192.168.0.0/24`), varios separados
por espacio, o la ruta a un fichero con uno por línea. **s** detiene el escaneo en curso.

Sobre los avisos: *VULN* = lo confirma un script NSE; *CVSS* sale del número de versión y en
Debian/Ubuntu suele exagerar (no ve los parches aplicados).
"""

    def actions(self):
        obj = Param("objetivo", "Objetivo", suggest=_subnets,
                    help="IP, red (192.168.0.0/24), rango, varios separados por espacio o ruta a un fichero")
        exc = Param("excluir", "Excluir (opcional, separados por coma)", required=False)
        return [
            Action("descubrir", "Descubrir equipos", descubrir, params=[obj, exc, scope.ok_param()],
                   help="Quién está encendido en la red, sin escanear puertos."),
            Action("escanear", "Escanear", escanear, params=[
                obj, Param("perfil", "Perfil", "choice", "estandar",
                           choices=[(k, v[0]) for k, v in PROFILES.items()
                                    if k in LIGHT_PROFILES or edition.allowed_full()[0]]), exc, scope.ok_param()],
                confirm=_confirm, help="Escaneo con un perfil predefinido; guarda los resultados y muestra el resumen."),
            Action("personalizado", "Escaneo personalizado", personalizado, full=True, params=[
                obj, Param("opciones", "Opciones de nmap", help="Ej.: -sS -p 22,80,443 -sV --script ssl-enum-ciphers"),
                exc, scope.ok_param()],
                help="Para expertos: opciones libres de nmap (la salida la gestiona la herramienta)."),
            Action("alcance", "Alcance autorizado", alcance, group="Configuración", params=[
                Param("accion", "Qué hacer", "choice", "ver", required=False,
                      choices=[("ver", "Ver el alcance actual"), ("añadir", "Añadir una red autorizada"),
                               ("quitar", "Quitar una red autorizada")]),
                Param("red", "Red en CIDR (al añadir o quitar)", required=False, help="Ej.: 10.20.0.0/16")],
                help="Define sobre qué redes está autorizado escanear y probar. Lo demás se bloquea."),
            Action("ver", "Ver escaneos guardados", ver, params=[
                Param("escaneo", "Número (vacío = listar)", required=False)]),
            Action("comparar", "Comparar escaneos", comparar, params=[
                Param("anterior", "Escaneo anterior (nº)", "int", 2), Param("reciente", "Escaneo reciente (nº)", "int", 1)],
                help="Qué ha cambiado entre dos escaneos (mira los números en 'Ver escaneos guardados')."),
        ]
