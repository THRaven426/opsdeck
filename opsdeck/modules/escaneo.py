"""Escaneo de red con nmap: descubrir equipos, perfiles de escaneo, resumen compacto y comparar escaneos.

Cada escaneo se guarda (XML, texto y grepable) en /var/lib/opsdeck/resultados/escaneo/ y se resume
leyendo el XML. Solo contra sistemas propios o con autorización por escrito."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Optional

import ipaddress

from ..core import audit, config, edition, feeds, nmapxml, recomendacion, results, scope, system, tooling
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
    "scripts": ("Scripts seguros: 1000 puertos + versiones + scripts por defecto (-sC)",
                ["-sS", "-sV", "-sC", "-T4", "--top-ports", "1000", "--open"]),
    "infraestructura": ("Infraestructura: puertos de gestión y servicios de red habituales en auditorías",
                        ["-sS", "-sU", "-sV", "-T4", "--open", "-p", "T:21-23,25,53,80,88,110,111,135,139,143,389,443,"
                         "445,465,587,623,636,873,993,995,1433,1521,2049,2375,2376,3000,3260,3268,3269,3306,3389,"
                         "5432,5900,5985,5986,6379,8000,8006,8080,8443,9000,9090,9200,9392,9443,10000,11211,27017,"
                         "U:53,69,123,161,500,623,1900,5353"]),
}
LIGHT_PROFILES = ("rapido", "estandar")
FORBIDDEN = ("-o", "-iL", "-iR", "--script-updatedb", "--datadir", "--resume", "--stylesheet")
TIMINGS = [("", "La del perfil"), ("T0", "T0 paranoico (IDS)"), ("T1", "T1 sigiloso"), ("T2", "T2 educado"),
           ("T3", "T3 normal"), ("T4", "T4 agresivo (red buena)"), ("T5", "T5 loco (puede perder puertos)")]
PORTS_RE = re.compile(r"^[TUSU:0-9,\-]+$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_,.()* -]+$")
DISCOVERY = [("completo", "ICMP + TCP + UDP (recomendado)"), ("arp", "Solo ARP (red local, el más fiable)"),
             ("icmp", "Solo ICMP (eco y marca de tiempo)"), ("tcp", "Solo TCP (cuando se filtra el ping)"),
             ("lista", "Sin enviar nada: solo resolver la lista (-sL)")]


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
    results.write(d / "orden.txt", " ".join(shlex.quote(a) for a in cmd_line) + "\n")
    ctx.out.info("$ " + " ".join(shlex.quote(a) for a in cmd_line))
    rc, _ = stream(ctx, cmd_line, accion=f"nmap_{label}", objetivo=" ".join(targets), detalle=" ".join(args),
                   keep=60)
    return rc, out.with_suffix(".xml")


def _set_flag(args: list[str], prefix: str, new: list[str]) -> list[str]:
    """Sustituye una opción del perfil (p. ej. -T4 por -T2) o la añade."""
    out, skip = [], False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a.startswith(prefix):
            if prefix in ("--top-ports", "-p", "--max-retries", "--min-rate", "--host-timeout",
                          "--version-intensity", "--script", "--script-args") and a == prefix:
                skip = True
            continue
        out.append(a)
    return out + new


def advanced(ctx: Context, v: dict, base: list[str]) -> Optional[list[str]]:
    """Aplica las opciones avanzadas sobre los argumentos de un perfil. None si hay un error."""
    args = list(base)
    ports = (v.get("puertos") or "").replace(" ", "")
    if ports:
        if not PORTS_RE.match(ports):
            ctx.out.error("Puertos no válidos. Ej.: 22,80,443  1-1024  T:80,U:161  o «-» para todos")
            return None
        args = _set_flag(_set_flag(args, "--top-ports", []), "-F", [])
        args = _set_flag(args, "-p", ["-p-"] if ports in ("-", "todos", "all") else ["-p", ports])
    if v.get("tiempo"):
        args = [a for a in args if not re.match(r"^-T[0-5]$", a)] + [f"-{v['tiempo']}"]
    if v.get("sin_ping") and "-Pn" not in args:
        args.append("-Pn")
    if v.get("sin_dns") and "-n" not in args:
        args.append("-n")
    if v.get("so") and "-O" not in args:
        args += ["-O", "--osscan-limit"]
    if v.get("ipv6") and "-6" not in args:
        args.append("-6")
    if v.get("versiones_todas") and "-sV" in args:
        args = _set_flag(args, "--version-intensity", ["--version-all"])
    if v.get("todos_los_estados"):
        args = [a for a in args if a != "--open"]
    scripts = (v.get("scripts") or "").strip()
    if scripts:
        if not SCRIPT_RE.match(scripts):
            ctx.out.error("Scripts NSE no válidos. Ej.: ssl-enum-ciphers,ssh2-enum-algos  o  \"default and safe\"")
            return None
        if "--script" in args:
            i = args.index("--script")
            args[i + 1] = f"({args[i + 1]}) or ({scripts})"
        else:
            args += ["--script", scripts]
    sargs = (v.get("script_args") or "").strip()
    if sargs:
        args += ["--script-args", sargs]
    for key, flag, lo, hi in (("min_rate", "--min-rate", 1, 100000), ("reintentos", "--max-retries", 0, 10)):
        if str(v.get(key) or "").strip():
            args = _set_flag(args, flag, [flag, str(tooling.int_in(v[key], 0, lo, hi))])
    ht = (v.get("tiempo_equipo") or "").strip()
    if ht:
        if not re.match(r"^\d+[smh]?$", ht):
            ctx.out.error("Tiempo máximo por equipo no válido. Ej.: 30m, 900s, 1h")
            return None
        args = _set_flag(args, "--host-timeout", ["--host-timeout", ht])
    iface = (v.get("interfaz") or "").strip()
    if iface:
        if not re.match(r"^[A-Za-z0-9_.:-]{1,20}$", iface):
            ctx.out.error("Interfaz no válida")
            return None
        args += ["-e", iface]
    extra, err = tooling.extra_args(v.get("extra", ""), FORBIDDEN)
    if err:
        ctx.out.error(err)
        return None
    return args + extra


def advanced_params() -> list[Param]:
    A = dict(required=False, advanced=True)
    return [
        Param("puertos", "Puertos (sustituye a los del perfil)", **A,
              help="Ej.: 22,80,443 · 1-1024 · T:80,443,U:161 · «-» = los 65535"),
        Param("tiempo", "Velocidad (plantilla de tiempo)", "choice", "", choices=TIMINGS, **A),
        Param("sin_ping", "No hacer ping previo (-Pn): trata a todos como encendidos", "bool", False, **A),
        Param("sin_dns", "No resolver nombres (-n), más rápido", "bool", False, **A),
        Param("so", "Detectar el sistema operativo (-O)", "bool", False, **A),
        Param("versiones_todas", "Detección de versiones exhaustiva (--version-all)", "bool", False, **A),
        Param("todos_los_estados", "Mostrar también puertos filtrados/cerrados", "bool", False, **A),
        Param("scripts", "Scripts NSE adicionales", **A,
              help="Ej.: ssl-enum-ciphers,ssh2-enum-algos,rdp-enum-encryption · o una expresión: \"safe and discovery\""),
        Param("script_args", "Argumentos de los scripts (--script-args)", **A, help="Ej.: http.useragent=Mozilla/5.0"),
        Param("min_rate", "Paquetes por segundo mínimos (--min-rate)", "int", "", **A),
        Param("reintentos", "Reintentos máximos por puerto (--max-retries)", "int", "", **A),
        Param("tiempo_equipo", "Tiempo máximo por equipo (--host-timeout)", **A, help="Ej.: 30m"),
        Param("interfaz", "Interfaz de red (-e)", **A),
        Param("ipv6", "Objetivos IPv6 (-6)", "bool", False, **A),
        tooling.p_extra("nmap", "--reason --data-length 25"),
    ]


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
    probes = {"completo": ["-sn", "-PE", "-PP", "-PS21,22,80,443,445,3389,8080", "-PA80,443", "-PU53,161"],
              "arp": ["-sn", "-PR"], "icmp": ["-sn", "-PE", "-PP", "--disable-arp-ping"],
              "tcp": ["-sn", "-PS21,22,25,80,135,139,443,445,3389,5985,8080,8443", "-PA80,443", "--disable-arp-ping"],
              "lista": ["-sL"]}
    base = probes.get(v.get("metodo") or "completo", probes["completo"])
    args = list(base)
    if v.get("sin_dns"):
        args.append("-n")
    if v.get("tiempo"):
        args.append(f"-{v['tiempo']}")
    extra, err = tooling.extra_args(v.get("extra", ""), FORBIDDEN)
    if err:
        ctx.out.error(err)
        return False
    rc, xml = _run(ctx, "descubrimiento", args + extra, t, v.get("excluir", ""), d, "descubrimiento")
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
    if prof != "completo" and advanced(ctx, v, PROFILES[prof][1]) is None:
        return False
    if prof == "completo":
        phase1 = advanced(ctx, {k: v.get(k) for k in ("tiempo", "sin_ping", "min_rate", "reintentos", "tiempo_equipo",
                                                      "interfaz", "ipv6", "puertos")},
                          ["-sS", "-p-", "-T4", "--min-rate", "1000", "--open", "-n"])
        if phase1 is None:
            return False
        rc, xml = _run(ctx, "completo_puertos", phase1, t, v.get("excluir", ""), d, "1_puertos")
        first = nmapxml.parse(xml)
        ports = sorted({p.port for h in first.up() for p in h.open_ports()})
        hosts = [h.ip for h in first.up() if h.open_ports()]
        if rc != 0 or not ports:
            if not ports:
                ctx.out.warn("No se encontraron puertos abiertos.")
            summary(ctx, first)
            return rc == 0
        ctx.out.info(f"Puertos abiertos: {','.join(map(str, ports))}. Analizando servicios en {len(hosts)} equipos...")
        phase2 = advanced(ctx, {**v, "puertos": ""}, ["-sS", "-sV", "-sC", "-O", "-T4", "-p", ",".join(map(str, ports))])
        rc, xml = _run(ctx, "completo_servicios", phase2 or [], hosts, "", d, "2_servicios")
    else:
        rc, xml = _run(ctx, prof, advanced(ctx, v, PROFILES[prof][1]) or [], t, v.get("excluir", ""), d, prof)
    summary(ctx, nmapxml.parse(xml))
    ctx.out.info(f"Resultados completos en {d}")
    return rc == 0


def personalizado(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "personalizado"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    flags, err = tooling.extra_args(v["opciones"], FORBIDDEN)
    if err:
        ctx.out.error(err)
        return False
    if not flags:
        ctx.out.error("Indica las opciones de nmap")
        return False
    d = results.new_dir("escaneo", f"personalizado_{v['objetivo'].replace('/', '_')}")
    rc, xml = _run(ctx, "personalizado", flags, t, v.get("excluir", ""), d, "personalizado")
    summary(ctx, nmapxml.parse(xml))
    return rc == 0


def escaneos(con_puertos: bool = True) -> list[Path]:
    """XML de los escaneos guardados, el más reciente primero. Por defecto solo los que miran puertos:
    un «Descubrir equipos» no tiene servicios y no sirve de base a nuclei, web, TLS..."""
    out = []
    for s in results.sessions("escaneo", 50):
        xmls = sorted(s.glob("*.xml"))
        if not xmls:
            continue
        if con_puertos and xmls[-1].name.startswith("descubrimiento"):
            continue
        out.append(xmls[-1])
    return out


def ultimo(ctx: Context) -> Optional[nmapxml.Scan]:
    """El último escaneo con puertos, avisando de cuál se usa. None (con mensaje) si no hay."""
    scans = escaneos()
    if not scans:
        ctx.out.error("No hay escaneos de puertos guardados: haz antes un «Escaneo de red › Escanear» "
                      "(perfil estándar o superior). Un «Descubrir equipos» no sirve: no mira puertos.")
        return None
    ctx.out.info(f"Usando el escaneo {_label(scans[0])}")
    return nmapxml.parse(scans[0])


def _label(p: Path) -> str:
    n = p.parent.name
    return f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}  {n[16:]}"


def ver(ctx: Context, v: dict) -> bool:
    scans = escaneos(con_puertos=False)
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
    scans = escaneos(con_puertos=False)
    try:
        a, b = int(v.get("anterior") or 2), int(v.get("reciente") or 1)
        old, new = scans[a - 1], scans[b - 1]
    except (ValueError, IndexError):
        ctx.out.error("Hacen falta dos escaneos guardados (míralos en 'Ver escaneos guardados').")
        return False
    ctx.out.info(f"Antes:   {_label(old)}\nDespués: {_label(new)}")
    disc = [p.name.startswith("descubrimiento") for p in (old, new)]
    if disc[0] != disc[1]:
        ctx.out.warn("Comparas un «Descubrir equipos» (sin puertos) con un escaneo de puertos: solo tiene "
                     "sentido la parte de equipos nuevos/desaparecidos.")
    c = nmapxml.diff(nmapxml.parse(old), nmapxml.parse(new))
    if disc[0] != disc[1]:
        c["puertos_abiertos"], c["puertos_cerrados"], c["versiones"] = [], [], []
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
| Scripts seguros | Como estándar, más los scripts NSE por defecto (`-sC`): títulos web, certificados, SMB... |
| Infraestructura | Puertos de gestión y servicios que suelen salir en las auditorías (RDP, iSCSI, SNMP, IPMI, NFS, bases de datos, Docker, Redis...), TCP y UDP |

**Opciones avanzadas** (casilla «Mostrar opciones avanzadas» del formulario, o `--opcion` en la línea
de comandos): puertos concretos, velocidad (T0–T5), sin ping (`-Pn`), sin DNS, detección de sistema
operativo, scripts NSE adicionales y sus argumentos, paquetes por segundo, reintentos, tiempo máximo
por equipo, interfaz, IPv6 y opciones libres de nmap. Sin tocarlas, cada perfil usa sus valores.

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
        A = dict(required=False, advanced=True)
        return [
            Action("descubrir", "Descubrir equipos", descubrir, params=[
                obj, exc, scope.ok_param(),
                Param("metodo", "Método de descubrimiento", "choice", "completo", choices=DISCOVERY, **A),
                Param("tiempo", "Velocidad (plantilla de tiempo)", "choice", "", choices=TIMINGS, **A),
                Param("sin_dns", "No resolver nombres (-n)", "bool", False, **A),
                tooling.p_extra("nmap", "--source-port 53")],
                help="Quién está encendido en la red, sin escanear puertos."),
            Action("escanear", "Escanear", escanear, params=[
                obj, Param("perfil", "Perfil", "choice", "estandar",
                           choices=[(k, v[0]) for k, v in PROFILES.items()
                                    if k in LIGHT_PROFILES or edition.allowed_full()[0]]), exc, scope.ok_param(),
                *advanced_params()],
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
