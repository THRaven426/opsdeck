"""Vulnerabilidades con nuclei: plantillas de la comunidad sobre webs y servicios.

Modos: análisis general por severidad, análisis dirigido por lo que encontró el último escaneo
(etiquetas según los productos detectados), paneles y configuraciones por defecto, y una consulta
de las plantillas/etiquetas disponibles. Todas las opciones de nuclei relevantes (etiquetas,
plantillas, protocolos, velocidad, cabeceras, proxy...) están en las opciones avanzadas."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from ..core import audit, feeds, nmapxml, recomendacion, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from .escaneo import ultimo

SEVERITIES = [("critical,high", "Crítica y alta"), ("critical,high,medium", "Crítica, alta y media"),
              ("critical,high,medium,low", "Todas salvo informativas"), ("info,low,medium,high,critical", "Todas")]
PROTOCOLS = [("", "Todos"), ("http", "Solo HTTP"), ("network", "Red (TCP: servicios)"), ("ssl", "SSL/TLS"),
             ("dns", "DNS"), ("javascript", "JavaScript (comprobaciones de red avanzadas)")]
TAG_RE = re.compile(r"^[A-Za-z0-9_.,:-]*$")
PATH_RE = re.compile(r"^[A-Za-z0-9_./,~-]*$")
FORBIDDEN = tooling.COMMON_FORBIDDEN + ("-u", "-target", "-update", "-up", "-ut", "-update-templates",
                                        "-lfa", "-allow-local-file-access", "-code",
                                        "-config", "-uc", "-uncover", "-uq", "-uncover-query", "-ue", "-uncover-engine",
                                        "-me", "-markdown-export", "-je", "-json-export", "-jle", "-jsonl-export",
                                        "-se", "-sarif-export", "-srd", "-store-resp-dir", "-sresp", "-store-resp",
                                        "-elog", "-error-log", "-tlog", "-trace-log", "-project", "-project-path",
                                        "-resume", "-t", "-templates", "-w", "-workflows", "-turl", "-template-url",
                                        "-wurl", "-workflow-url", "-ev", "-env-vars", "-headless", "-sb",
                                        "-system-chrome", "-cdp-endpoint", "-ldf", "-tp", "-profile",
                                        "-sf", "-secret-file", "-ps", "-passive")

# Producto detectado por nmap (en minúsculas) -> etiquetas de nuclei. Solo afina qué plantillas se usan;
# la detección la hacen las plantillas (que se actualizan a diario), no esta tabla.
PRODUCT_TAGS = [
    (r"openssh", "ssh,openssh"), (r"apache httpd|apache", "apache"), (r"nginx", "nginx"),
    (r"microsoft iis|iis", "iis"), (r"tomcat", "tomcat"), (r"jetty", "jetty"), (r"php", "php"),
    (r"grafana", "grafana"), (r"jenkins", "jenkins"), (r"gitlab", "gitlab"), (r"wordpress", "wordpress"),
    (r"ilo|integrated lights-out|hp-ilo", "ilo,hpe"), (r"idrac", "idrac,dell"), (r"vmware|esxi|vcenter", "vmware"),
    (r"proxmox", "proxmox"), (r"synology|diskstation", "synology"), (r"qnap", "qnap"), (r"veeam", "veeam"),
    (r"fortinet|fortigate|fortios", "fortinet"), (r"citrix|netscaler", "citrix"), (r"zimbra", "zimbra"),
    (r"exchange|outlook web", "exchange,microsoft"), (r"mysql|mariadb", "mysql"), (r"postgres", "postgres"),
    (r"microsoft sql|ms-sql", "mssql"), (r"redis", "redis"), (r"mongodb", "mongodb"),
    (r"elasticsearch", "elasticsearch"), (r"docker", "docker"), (r"kubernetes|kubelet", "kubernetes"),
    (r"rabbitmq", "rabbitmq"), (r"vsftpd|proftpd|pure-ftpd|ftp", "ftp"), (r"samba|smb|microsoft-ds", "smb"),
    (r"openssl", "openssl"), (r"minio", "minio"), (r"zabbix", "zabbix"), (r"nagios", "nagios"),
    (r"prometheus", "prometheus"), (r"kibana", "kibana"), (r"weblogic", "weblogic"), (r"sap", "sap"),
    (r"rdp|ms-wbt-server|terminal services", "rdp"), (r"snmp", "snmp"), (r"ldap", "ldap"),
    (r"webmin", "webmin"), (r"pfsense", "pfsense"), (r"mikrotik|routeros", "mikrotik"),
    (r"cisco", "cisco"), (r"ubiquiti|unifi", "ubiquiti"), (r"axis", "axis"), (r"hikvision", "hikvision"),
]


def actualizar(ctx: Context, v: dict) -> bool:
    rc, _ = stream(ctx, ["nuclei", "-update-templates", "-nc"], accion="nuclei_actualizar", objetivo="plantillas", keep=30)
    return rc == 0


def targets_from_scan(scan: nmapxml.Scan) -> list[str]:
    out = []
    for h in scan.up():
        for p in h.open_ports():
            if p.proto != "tcp":
                continue
            if p.is_web:
                out.append(f"{'https' if p.is_tls else 'http'}://{h.ip}:{p.port}")
            else:
                out.append(f"{h.ip}:{p.port}")
    return out


def tags_from_scan(scan: nmapxml.Scan) -> list[str]:
    tags: list[str] = []
    for h in scan.up():
        for p in h.open_ports():
            text = " ".join((p.service, p.product, p.version, " ".join(p.scripts.values())[:400])).lower()
            for pat, t in PRODUCT_TAGS:
                if re.search(pat, text):
                    tags += t.split(",")
    return list(dict.fromkeys(tags))


def _targets(ctx: Context, v: dict) -> tuple[list[str], str]:
    target = (v.get("objetivo") or "").strip()
    if target:
        if scope.is_target_file(target):
            items, problem = scope.read_target_file(target)
            if problem:
                ctx.out.error(problem)
                return [], ""
        else:
            items = target.split()
        label = target.replace("/", "_").replace(":", "_")[:40]
    else:
        scan = ultimo(ctx)
        if scan is None:
            return [], ""
        items, label = targets_from_scan(scan), "ultimo_escaneo"
        if not items:
            ctx.out.error("El último escaneo no tiene puertos TCP abiertos que analizar.")
            return [], ""
    if not scope.gate(ctx, " ".join(items), v, "nuclei"):
        return [], ""
    return items, label


def build_args(ctx: Context, v: dict, tfile: Path, out: Path, *, tags: str = "", severity: str = "") -> list[str]:
    """Orden de nuclei con las opciones elegidas. [] si alguna opción no es válida (con mensaje)."""
    args = ["nuclei", "-l", str(tfile), "-jsonl", "-o", str(out), "-nc", "-silent", "-stats", "-si", "30"]
    sev = severity if severity is not None else ""
    if sev:
        args += ["-severity", sev]
    for key, flag in (("etiquetas", "-tags"), ("excluir_etiquetas", "-etags"), ("ids", "-id"),
                      ("excluir_ids", "-eid")):
        val = (v.get(key) or "").replace(" ", "")
        if key == "etiquetas" and tags:
            val = ",".join(x for x in (val, tags) if x)
        if val:
            if not TAG_RE.match(val):
                ctx.out.error(f"Valor no válido en {flag}: {val}")
                return []
            args += [flag, val]
    tpl = (v.get("plantillas") or "").strip()
    if tpl:
        if not PATH_RE.match(tpl) or ".." in tpl or any(p.startswith(("/", "~")) for p in tpl.split(",")):
            ctx.out.error("Plantillas: indica rutas o carpetas separadas por coma (p. ej. http/cves/2025/,ssl/)")
            return []
        args += ["-t", tpl]
    if v.get("protocolo"):
        args += ["-type", v["protocolo"]]
    if v.get("excluir_sev"):
        args += ["-exclude-severity", v["excluir_sev"]]
    args += ["-rate-limit", str(tooling.int_in(v.get("velocidad"), 100, 1, 2000)),
             "-c", str(tooling.int_in(v.get("hilos"), 25, 1, 200)),
             "-timeout", str(tooling.int_in(v.get("espera"), 10, 1, 120)),
             "-retries", str(tooling.int_in(v.get("reintentos"), 1, 0, 5))]
    if v.get("sin_interactsh", True):
        args.append("-no-interactsh")
    if v.get("headless"):
        args.append("-headless")
    if v.get("redirecciones"):
        args.append("-follow-redirects")
    if v.get("automatico"):
        args.append("-as")
    hdrs, err = tooling.headers(v.get("cabeceras", ""))
    if err:
        ctx.out.error(err)
        return []
    for h in hdrs:
        args += ["-H", h]
    px, err = tooling.proxy(v.get("proxy", ""))
    if err:
        ctx.out.error(err)
        return []
    if px:
        args += ["-proxy", px]
    extra, err = tooling.extra_args(v.get("extra", ""), FORBIDDEN)
    if err:
        ctx.out.error(err)
        return []
    return args + extra


def _run(ctx: Context, v: dict, label: str, *, tags: str = "", severity: str = "", accion: str = "nuclei_analizar",
         targets: list[str] | None = None, tlabel: str = "") -> bool:
    if targets is None:
        targets, tlabel = _targets(ctx, v)
    if not targets:
        return False
    feeds.warn_if_stale(ctx)
    d = results.new_dir("nuclei", f"{label}_{tlabel}")
    tfile = d / "objetivos.txt"
    results.write(tfile, "\n".join(targets) + "\n")
    out = d / "hallazgos.jsonl"
    args = build_args(ctx, v, tfile, out, tags=tags, severity=severity)
    if not args:
        return False
    results.write(d / "orden.txt", " ".join(tooling.redact(args)) + "\n")
    tooling.show_cmd(ctx, args)
    ctx.out.info(f"Analizando {len(targets)} objetivos" + (f" (severidad: {severity})" if severity else "")
                 + (f" · etiquetas: {tags}" if tags else "") + "; s = detener...")
    rc, _ = stream(ctx, args, accion=accion, objetivo=tlabel, detalle=" ".join(tooling.redact(args[9:]))[:300], keep=80)
    return report(ctx, out, tlabel, rc)


def report(ctx: Context, out: Path, target: str, rc: int = 0) -> bool:
    findings = []
    if out.exists():
        for line in out.read_text(errors="replace").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not findings:
        ctx.out.ok("nuclei no ha encontrado nada con esos criterios.")
        return rc == 0
    sev = Counter(f.get("info", {}).get("severity", "?") for f in findings)
    ctx.out.title("Hallazgos por severidad: " + "  ".join(f"{k}={sev[k]}" for k in
                                                         ("critical", "high", "medium", "low", "info") if sev.get(k)))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = []
    for f in sorted(findings, key=lambda f: order.get(f.get("info", {}).get("severity"), 9)):
        info = f.get("info", {})
        extra = f.get("extracted-results") or []
        rows.append([info.get("severity", "?"), f.get("matched-at", f.get("host", "?"))[:50],
                     (info.get("name", f.get("template-id", "?")) + (f" [{', '.join(map(str, extra))[:40]}]" if extra else ""))[:80],
                     f.get("template-id", "")[:30]])
    ctx.out.table(["Severidad", "Dónde", "Qué", "Plantilla"], rows[:100])
    audit.record("nuclei_resultado", target, "OK", " ".join(f"{k}={n}" for k, n in sev.items()))
    ctx.out.info(f"Detalle (referencias, petición y respuesta) en {out}")
    recomendacion.render(ctx, recomendacion.from_nuclei(findings))
    return True


def analizar(ctx: Context, v: dict) -> bool:
    return _run(ctx, v, "analisis", severity=v.get("severidad") or "critical,high")


def dirigido(ctx: Context, v: dict) -> bool:
    scan = ultimo(ctx)
    if scan is None:
        return False
    tags = tags_from_scan(scan)
    if not tags:
        ctx.out.warn("No se reconoce ningún producto en el último escaneo (¿se hizo con detección de versiones?). "
                     "Usa el perfil «estándar» o superior, o «Analizar» por severidad.")
        return False
    ctx.out.info("Productos detectados → etiquetas: " + ", ".join(tags))
    targets = targets_from_scan(scan)
    if not scope.gate(ctx, " ".join(targets), v, "nuclei"):
        return False
    return _run(ctx, v, "dirigido", tags=",".join(tags), severity=v.get("severidad") or "",
                targets=targets, tlabel="ultimo_escaneo", accion="nuclei_dirigido")


def paneles(ctx: Context, v: dict) -> bool:
    tags = {"paneles": "panel,exposure,config,misconfig", "credenciales": "default-login",
            "tecnologias": "tech", "tokens": "token,exposure,keys,disclosure"}[v.get("tipo") or "paneles"]
    return _run(ctx, v, v.get("tipo") or "paneles", tags=tags, severity="", accion=f"nuclei_{v.get('tipo')}")


def plantillas(ctx: Context, v: dict) -> bool:
    filtro = (v.get("etiquetas") or "").replace(" ", "")
    if filtro and not TAG_RE.match(filtro):
        ctx.out.error("Etiquetas no válidas")
        return False
    if v.get("modo") == "etiquetas":
        args = ["nuclei", "-tgl", "-nc", "-silent"]
    else:
        args = ["nuclei", "-tl", "-nc", "-silent"] + (["-tags", filtro] if filtro else []) + \
               (["-severity", v["severidad"]] if v.get("severidad") else [])
    r = system.run(args, timeout=300)
    lines = [l for l in r.out.splitlines() if l.strip()]
    if not lines:
        ctx.out.error("nuclei no devolvió nada: ¿plantillas descargadas? (Actualizar plantillas)\n" + r.text[-400:])
        return False
    for l in lines[:300]:
        ctx.out.line("  " + l)
    ctx.out.info(f"{len(lines)} líneas" + (" (se muestran 300)" if len(lines) > 300 else "")
                 + ". Usa estos valores en las opciones avanzadas (etiquetas, plantillas, IDs).")
    return True


def adv_params(sev_default: bool = False) -> list[Param]:
    A = dict(required=False, advanced=True)
    return [
        Param("etiquetas", "Etiquetas a incluir (-tags)", **A, help="Ej.: cve,rce,lfi · panel · default-login · grafana"),
        Param("excluir_etiquetas", "Etiquetas a excluir (-etags)", "text", "dos,fuzz,intrusive", **A,
              help="Por defecto se excluyen las que pueden tumbar o alterar el servicio."),
        Param("ids", "Solo estas plantillas por ID (-id)", **A, help="Ej.: CVE-2024-3400,tls-version"),
        Param("excluir_ids", "Excluir plantillas por ID (-eid)", **A),
        Param("plantillas", "Rutas de plantillas (-t)", **A, help="Ej.: http/cves/2025/,ssl/,network/  (relativas al repositorio de plantillas)"),
        Param("protocolo", "Tipo de plantilla (-type)", "choice", "", choices=PROTOCOLS, **A),
        Param("excluir_sev", "Excluir severidades", "choice", "", choices=[("", "Ninguna"), ("info", "Informativas"),
                                                                         ("info,low", "Informativas y bajas")], **A),
        tooling.p_rate(100), tooling.p_threads(25), tooling.p_timeout(10),
        Param("reintentos", "Reintentos", "int", 1, **A),
        Param("redirecciones", "Seguir redirecciones HTTP", "bool", False, **A),
        Param("automatico", "Selección automática según tecnologías detectadas (-as, usa wappalyzer)", "bool", False, **A),
        Param("headless", "Plantillas con navegador (-headless, necesita Chrome)", "bool", False, **A),
        Param("sin_interactsh", "Sin interactsh (no usa servidores externos para pruebas fuera de banda)", "bool", True, **A,
              help="Desmárcalo para detectar fallos ciegos (SSRF, RCE ciega); nuclei usará oast.* en internet."),
        tooling.p_headers(), tooling.p_proxy(),
        tooling.p_extra("nuclei", "-mhe 5 -project"),
    ]


class Nuclei(Module):
    full = True
    id = "nuclei"
    name = "Vulnerabilidades (nuclei)"
    category = "Ciberseguridad"
    summary = "Detecta vulnerabilidades conocidas y configuraciones inseguras con plantillas"
    requires = [cmd("nuclei", debian="nuclei", arch="nuclei", label="nuclei")]
    families = ("debian", "arch")
    help = """\
# Vulnerabilidades (nuclei)

> Solo contra sistemas propios o con autorización por escrito.

nuclei comprueba miles de **vulnerabilidades conocidas** (CVE), paneles expuestos, configuraciones
por defecto y fallos comunes, usando plantillas que mantiene la comunidad.

1. **Actualizar plantillas** la primera vez y de vez en cuando.
2. **Analizar**: sobre URLs/equipos (o un fichero con uno por línea) o, si lo dejas vacío, sobre
   **todos los servicios del último escaneo de puertos**. Empieza por severidad crítica y alta.
3. **Análisis dirigido por el escaneo**: mira qué productos detectó nmap (OpenSSH, PHP, Grafana,
   iLO, Synology, Veeam...) y lanza solo las plantillas de esos productos, de cualquier severidad.
   Es el equivalente a «comprobar lo que dice Nessus/OpenVAS sobre estas versiones».
4. **Paneles, credenciales por defecto y fugas**: paneles de administración expuestos, servicios con
   la contraseña de fábrica (`default-login`), ficheros y claves expuestos.
5. **Plantillas y etiquetas disponibles**: para elegir qué lanzar en las opciones avanzadas.

**Opciones avanzadas**: etiquetas a incluir/excluir, plantillas por ID o por carpeta, tipo de
plantilla (http, red, ssl, dns), peticiones por segundo, concurrencia, tiempos, reintentos,
redirecciones, selección automática por tecnología (`-as`), plantillas con navegador, pruebas fuera
de banda (interactsh), cabeceras (cookies/tokens para zonas autenticadas), proxy (Burp/ZAP) y
opciones libres. Por defecto se excluyen las etiquetas `dos`, `fuzz` e `intrusive`.

A diferencia del "CVSS" del escaneo de nmap (que solo mira el número de versión), nuclei
**comprueba** el fallo, así que sus hallazgos son mucho más fiables.
"""

    def actions(self):
        obj = Param("objetivo", "Objetivo (vacío = servicios del último escaneo)", required=False,
                    help="URL, equipo:puerto, varios separados por espacio o ruta a un fichero con uno por línea")
        ok = scope.ok_param()
        sev = Param("severidad", "Severidad", "choice", "critical,high", choices=SEVERITIES)
        confirm = lambda v: (f"nuclei enviará pruebas activas a {v.get('objetivo') or 'los servicios del último escaneo'}. "
                             "¿Tienes autorización?")
        return [
            Action("actualizar", "Actualizar plantillas", actualizar, changes=True,
                   confirm="Se descargarán las últimas plantillas de nuclei. ¿Continuar?"),
            Action("analizar", "Analizar", analizar, params=[obj, sev, ok, *adv_params()], confirm=confirm),
            Action("dirigido", "Análisis dirigido por el último escaneo", dirigido, params=[
                Param("severidad", "Severidad", "choice", "", choices=[("", "Todas")] + SEVERITIES), ok,
                *[p for p in adv_params() if p.name not in ("etiquetas",)]],
                confirm="nuclei lanzará las plantillas de los productos detectados en el último escaneo. ¿Tienes autorización?",
                help="Solo las plantillas de los productos que detectó nmap (OpenSSH, PHP, Grafana, iLO...)."),
            Action("paneles", "Paneles, credenciales por defecto y fugas", paneles, params=[
                obj, Param("tipo", "Qué buscar", "choice", "paneles", choices=[
                    ("paneles", "Paneles y configuraciones expuestas"),
                    ("credenciales", "Credenciales por defecto (intenta iniciar sesión con las de fábrica)"),
                    ("tokens", "Claves, tokens y ficheros expuestos"),
                    ("tecnologias", "Solo identificar tecnologías")]), ok,
                *[p for p in adv_params() if p.name not in ("etiquetas",)]],
                confirm=lambda v: ("Se intentará iniciar sesión con credenciales de fábrica: puede bloquear cuentas o "
                                   "generar alertas. ¿Tienes autorización?") if v.get("tipo") == "credenciales"
                else confirm(v)),
            Action("plantillas", "Plantillas y etiquetas disponibles", plantillas, params=[
                Param("modo", "Ver", "choice", "plantillas", choices=[("plantillas", "Plantillas"), ("etiquetas", "Etiquetas")]),
                Param("etiquetas", "Filtrar por etiquetas", required=False, help="Ej.: grafana,cve"),
                Param("severidad", "Filtrar por severidad", "choice", "", required=False,
                      choices=[("", "Todas")] + SEVERITIES)]),
        ]
