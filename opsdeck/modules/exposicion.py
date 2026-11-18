"""Servicios expuestos: comprobaciones por servicio de lo que suelen reportar Nessus y OpenVAS.

Para cada servicio que aparece abierto (RDP, iSCSI, SNMP, NFS, LDAP, DNS, NTP, FTP, TFTP, bases de
datos, Redis, MongoDB, Docker, VNC, IPMI, UPnP, SMTP, SMB, RMI, rsync, X11, MQTT, AJP...) lanza los
scripts NSE que confirman la debilidad típica (sin autenticación, NLA desactivado, comunidad por
defecto, exportaciones abiertas, recursión, monlist...). Además: fugas de información de red (marcas
de tiempo ICMP y TCP) y descubrimiento de protocolos de difusión (mDNS, UPnP, NetBIOS, DHCP).

Las comprobaciones que intentan credenciales por defecto o una acción (relay SMTP) van aparte y piden
confirmación. Nada se explota: se confirma y se recomienda."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core import audit, nmapxml, recomendacion, results, scope, tooling
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from ..core.recomendacion import Finding
from .escaneo import _subnets, _targets, escaneos


@dataclass
class Check:
    id: str
    nombre: str
    tcp: list[int] = field(default_factory=list)
    udp: list[int] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    cred_scripts: list[str] = field(default_factory=list)      # credenciales por defecto (con confirmación)
    intrusive_scripts: list[str] = field(default_factory=list)  # hacen algo más que preguntar (con confirmación)
    services: tuple[str, ...] = ()


CHECKS = [
    Check("rdp", "Escritorio remoto (RDP): NLA y cifrado", [3389], [], ["rdp-enum-encryption", "rdp-ntlm-info"],
          services=("ms-wbt-server", "rdp")),
    Check("smb", "SMB: SMBv1 y firma", [139, 445], [], ["smb-protocols", "smb2-security-mode", "smb-security-mode"],
          services=("microsoft-ds", "netbios-ssn")),
    Check("netbios", "NetBIOS: nombre y dominio", [], [137], ["nbstat"], services=("netbios-ns",)),
    Check("iscsi", "iSCSI: destinos sin autenticación", [3260], [], ["iscsi-info"], services=("iscsi",)),
    Check("snmp", "SNMP: comunidad por defecto y datos expuestos", [], [161], ["snmp-info", "snmp-sysdescr"],
          cred_scripts=["snmp-brute"], services=("snmp",)),
    Check("nfs", "NFS y RPC: exportaciones", [111, 2049], [111], ["nfs-showmount", "rpcinfo"],
          services=("rpcbind", "nfs", "mountd")),
    Check("ldap", "LDAP: información y consultas anónimas", [389, 3268], [], ["ldap-rootdse", "ldap-search"],
          services=("ldap",)),
    Check("dns", "DNS: recursión abierta y transferencia de zona", [53], [53], ["dns-recursion", "dns-nsid"],
          services=("domain",)),
    Check("ntp", "NTP: monlist (amplificación) y versión", [], [123], ["ntp-info", "ntp-monlist"], services=("ntp",)),
    Check("ftp", "FTP: acceso anónimo", [21], [], ["ftp-anon", "ftp-syst"], services=("ftp",)),
    Check("tftp", "TFTP: ficheros accesibles", [], [69], ["tftp-enum"], services=("tftp",)),
    Check("mssql", "SQL Server: versión e información", [1433], [1434], ["ms-sql-info", "ms-sql-ntlm-info"],
          cred_scripts=["ms-sql-empty-password"], services=("ms-sql-s", "ms-sql-m")),
    Check("mysql", "MySQL/MariaDB: versión", [3306], [], ["mysql-info"], cred_scripts=["mysql-empty-password"],
          services=("mysql",)),
    Check("redis", "Redis sin contraseña", [6379], [], ["redis-info"], services=("redis",)),
    Check("mongodb", "MongoDB sin autenticación", [27017], [], ["mongodb-info", "mongodb-databases"],
          services=("mongodb", "mongod")),
    Check("memcached", "Memcached expuesto", [11211], [11211], ["memcached-info"], services=("memcached",)),
    Check("docker", "API de Docker sin protección", [2375], [], ["docker-version"], services=("docker",)),
    Check("elastic", "Elasticsearch sin autenticación", [9200], [], [], services=("elasticsearch",)),
    Check("vnc", "VNC: sin contraseña", [5900, 5901, 5902], [], ["vnc-info"], services=("vnc",)),
    Check("ipmi", "IPMI/BMC: cifrado 0 y exposición", [], [623], ["ipmi-version", "ipmi-cipher-zero"],
          services=("asf-rmcp", "ipmi")),
    Check("upnp", "UPnP: dispositivos que se anuncian", [], [1900], ["upnp-info"], services=("upnp",)),
    Check("smtp", "SMTP: comandos (VRFY/EXPN) y relay abierto", [25, 587], [], ["smtp-commands"],
          intrusive_scripts=["smtp-open-relay"], services=("smtp", "submission")),
    Check("rmi", "Java RMI: registro expuesto", [1099], [], ["rmi-dumpregistry"], services=("java-rmi", "rmiregistry")),
    Check("rsync", "rsync: módulos accesibles", [873], [], ["rsync-list-modules"], services=("rsync",)),
    Check("x11", "X11 abierto", [6000], [], ["x11-access"], services=("x11",)),
    Check("mqtt", "MQTT: acceso anónimo", [1883], [], ["mqtt-subscribe"], services=("mqtt",)),
    Check("ajp", "AJP (Tomcat): Ghostcat", [8009], [], ["ajp-headers"], services=("ajp13",)),
    Check("winrm", "WinRM por HTTP", [5985], [], [], services=("wsman",)),
    Check("telnet", "Telnet (en claro)", [23], [], ["telnet-encryption"], services=("telnet",)),
]
BY_ID = {c.id: c for c in CHECKS}


# ---------------------------------------------------------------- interpretación de cada script

def _f(obj, sev, title, tipo, **d) -> Finding:
    return Finding(obj, sev, title, tipo, datos=d)


def analyze(ip: str, p: nmapxml.Port, host_scripts: Optional[dict] = None) -> list[Finding]:
    """Hallazgos de un puerto según la salida de sus scripts NSE."""
    S = p.scripts
    obj = f"{ip}:{p.port}/{p.proto}" if p.proto == "udp" else f"{ip}:{p.port}"
    out: list[Finding] = []
    add = lambda *a, **k: out.append(_f(obj, *a, **k))
    t = S.get("rdp-enum-encryption", "")
    if t:
        if re.search(r"Native RDP: SUCCESS|\bSSL: SUCCESS", t):
            add("MEDIO", "RDP no exige autenticación a nivel de red (NLA)", "rdp_nla")
        if "Native RDP: SUCCESS" in t and re.search(r"(40|56)-bit RC4: SUCCESS|Encryption level: (Low|Client Compatible)", t):
            add("MEDIO", "RDP acepta seguridad nativa con cifrado débil (intermediario)", "rdp_cifrado")
    t = S.get("iscsi-info", "")
    if "NOT required" in t:
        tg = re.findall(r"(iqn\.[^\s:]+)", t)
        add("ALTO", f"Destino iSCSI sin autenticación: {', '.join(tg[:3]) or '?'}", "iscsi_sin_auth")
    if S.get("snmp-sysdescr", "").strip():
        add("ALTO", "SNMP responde con la comunidad por defecto «public»: " + S["snmp-sysdescr"].strip().splitlines()[0][:70],
            "snmp_comunidad")
    elif S.get("snmp-info", "").strip():
        add("BAJO", "SNMP expuesto (responde al descubrimiento)", "snmp_expuesto")
    t = S.get("snmp-brute", "")
    valid = re.findall(r"^\s*(\S+) - Valid credentials", t, re.M)
    if valid:
        add("ALTO", f"Comunidades SNMP válidas: {', '.join(valid)}", "snmp_comunidad")
    t = S.get("nfs-showmount", "")
    if t:
        exports = [l.strip() for l in t.splitlines() if l.strip().startswith("/")]
        open_ = [e for e in exports if re.search(r"\s(\*|everyone|0\.0\.0\.0/0)\s*$", e) or len(e.split()) == 1]
        if open_:
            add("ALTO", f"NFS exporta a cualquiera: {'; '.join(open_[:3])}", "nfs_export")
        elif exports:
            add("MEDIO", f"Exportaciones NFS visibles: {'; '.join(exports[:3])}", "nfs_export")
    t = S.get("ldap-search", "")
    if re.search(r"^\s*dn: ", t, re.M | re.I):
        n = len(re.findall(r"^\s*dn: ", t, re.M | re.I))
        add("ALTO", f"LDAP permite consultas anónimas ({n} objetos de muestra)", "ldap_anonimo")
    if S.get("ldap-rootdse") and p.port in (389, 3268) and not p.tunnel:
        add("INFO", "LDAP sin TLS en el puerto " + str(p.port) + " (comprueba que se exige firma/StartTLS)", "ldap_claro")
    if "Recursion appears to be enabled" in S.get("dns-recursion", ""):
        add("BAJO", "El DNS hace resolución recursiva para quien pregunte", "dns_recursion")
    t = S.get("dns-zone-transfer", "")
    if t and not re.search(r"(failed|refused|error)", t, re.I) and len(t.splitlines()) > 2:
        add("ALTO", f"Transferencia de zona permitida ({len(t.splitlines())} registros)", "dns_axfr")
    t = S.get("ntp-monlist", "")
    if t.strip() and re.search(r"(Target is synchronised|Public Servers|Private Servers|Public Clients|Private Clients)", t):
        add("MEDIO", "NTP responde a monlist (amplificación DDoS, CVE-2013-5211)", "ntp_monlist")
    if "Anonymous FTP login allowed" in S.get("ftp-anon", ""):
        add("MEDIO", "FTP permite acceso anónimo", "ftp_anonimo")
    t = S.get("tftp-enum", "")
    if t.strip():
        files = [l.strip() for l in t.splitlines() if l.strip()]
        add("MEDIO", f"TFTP sin autenticación, ficheros encontrados: {', '.join(files[:4])}", "tftp_abierto")
    for sid in ("ms-sql-empty-password", "mysql-empty-password"):
        if re.search(r"(Login Success|account has empty password|has empty password)", S.get(sid, "")):
            add("CRÍTICO", "Base de datos con usuario sin contraseña: " + S[sid].strip().splitlines()[-1][:60], "bd_sin_auth")
    if re.search(r"Version\s*:?\s*\d", S.get("redis-info", "")):
        add("ALTO", "Redis accesible sin contraseña", "bd_sin_auth")
    if re.search(r"(version|databases)", S.get("mongodb-info", "") + S.get("mongodb-databases", ""), re.I) and \
            "auth" not in (S.get("mongodb-databases", "") + S.get("mongodb-info", "")).lower():
        add("ALTO", "MongoDB accesible sin autenticación", "bd_sin_auth")
    if re.search(r"(Process ID|Uptime|Version)", S.get("memcached-info", "")):
        add("MEDIO", "Memcached accesible sin autenticación", "bd_sin_auth")
    if re.search(r"Version", S.get("docker-version", "")):
        add("CRÍTICO", "API de Docker accesible sin TLS ni autenticación (control total del equipo)", "docker_api")
    t = S.get("vnc-info", "")
    if t:
        sec = t.split("Security types:", 1)[1] if "Security types:" in t else ""
        if re.search(r"^\s*None\b", sec, re.M) or "does not require authentication" in t:
            add("ALTO", "VNC sin contraseña", "vnc_sin_auth")
    if "VULNERABLE" in S.get("ipmi-cipher-zero", ""):
        add("CRÍTICO", "IPMI acepta el cifrado 0 (sin contraseña)", "ipmi_cifrado0")
    elif S.get("ipmi-version", "").strip():
        add("MEDIO", "IPMI 2.0 expuesto (permite obtener hashes de contraseña, RAKP)", "ipmi_expuesto")
    if S.get("upnp-info", "").strip():
        add("BAJO", "Dispositivo UPnP que se anuncia: " + S["upnp-info"].strip().splitlines()[0][:60], "upnp")
    t = S.get("smtp-commands", "")
    if re.search(r"\b(VRFY|EXPN)\b", t):
        add("BAJO", "SMTP admite VRFY/EXPN (enumeración de usuarios)", "smtp_vrfy")
    if "Server is an open relay" in S.get("smtp-open-relay", ""):
        add("ALTO", "SMTP es un relay abierto", "smtp_relay")
    if S.get("rmi-dumpregistry", "").strip():
        add("MEDIO", "Registro Java RMI accesible", "rmi_registro")
    t = S.get("rsync-list-modules", "")
    if t.strip():
        add("MEDIO", "rsync lista módulos: " + ", ".join(l.split()[0] for l in t.splitlines() if l.strip())[:80],
            "rsync_modulos")
    if "access is granted" in S.get("x11-access", ""):
        add("ALTO", "Servidor X11 accesible por la red", "x11_abierto")
    if S.get("mqtt-subscribe", "").strip() and "error" not in S["mqtt-subscribe"].lower():
        add("ALTO", "Broker MQTT con acceso anónimo", "mqtt_anonimo")
    if S.get("ajp-headers", "").strip() or p.service == "ajp13":
        add("MEDIO", "Conector AJP expuesto (Ghostcat, CVE-2020-1938): confírmalo con nuclei", "servicio_info",
            exploit="Ghostcat AJP")
    if p.port == 5985 and p.proto == "tcp":
        add("INFO", "WinRM por HTTP (sin TLS)", "servicio_info")
    if p.service == "telnet" or p.port == 23:
        add("MEDIO", "Telnet: credenciales y sesión en claro", "servicio_inseguro")
    if "smb-protocols" in S or "smb2-security-mode" in S:
        from .smb import analyze_host
        h = nmapxml.Host(ip=ip, ports=[p], scripts={})
        h.scripts.update({k: v for k, v in S.items() if k.startswith("smb")})
        h.scripts.update(host_scripts or {})
        r = analyze_host(h)
        if r["smbv1"]:
            add("ALTO", "SMBv1 activo (WannaCry/EternalBlue)", "smbv1")
        if r["firma"] == "NO requerida":
            add("MEDIO", "Firma SMB no obligatoria (relay NTLM)", "smb_sin_firma")
    return out


def analyze_host_scripts(ip: str, scripts: dict) -> list[Finding]:
    out = []
    if scripts.get("nbstat", "").strip():
        m = re.search(r"NetBIOS name: (\S+?),", scripts["nbstat"])
        out.append(Finding(f"{ip}:137/udp", "INFO", f"NetBIOS revela nombre{': ' + m.group(1) if m else ''}",
                           "servicio_info"))
    sm = scripts.get("smb2-security-mode", "")
    if sm and "not required" in sm:
        out.append(Finding(f"{ip}:445", "MEDIO", "Firma SMB no obligatoria (relay NTLM)", "smb_sin_firma"))
    if "SMBv1" in scripts.get("smb-protocols", "") or "NT LM 0.12" in scripts.get("smb-protocols", ""):
        out.append(Finding(f"{ip}:445", "ALTO", "SMBv1 activo (WannaCry/EternalBlue)", "smbv1"))
    return out


def elastic(ip: str, port: int) -> list[Finding]:
    for scheme in ("http", "https"):
        try:
            from .web import request
            r = request(f"{scheme}://{ip}:{port}/", limit=8000, timeout=5)
            body = r.get("cuerpo", b"").decode("utf-8", "replace")
            if r.get("estado") == 200 and "cluster_name" in body:
                ver = re.search(r'"number"\s*:\s*"([^"]+)"', body)
                return [Finding(f"{ip}:{port}", "ALTO", "Elasticsearch accesible sin autenticación"
                                + (f" (versión {ver.group(1)})" if ver else ""), "bd_sin_auth")]
            if r.get("estado"):
                return []
        except Exception:
            continue
    return []


# ---------------------------------------------------------------- ejecución

def _selected(v: dict) -> list[Check]:
    sel = v.get("servicios") or "todos"
    return CHECKS if sel == "todos" else [BY_ID[x] for x in sel.split(",") if x in BY_ID]


def build_nmap(v: dict, checks: list[Check]) -> tuple[list[str], list[str]]:
    """(argumentos de nmap, scripts) para las comprobaciones elegidas."""
    tcp = sorted({p for c in checks for p in c.tcp})
    udp = sorted({p for c in checks for p in c.udp}) if v.get("udp", True) else []
    scripts = [s for c in checks for s in c.scripts]
    if v.get("credenciales"):
        scripts += [s for c in checks for s in c.cred_scripts]
    if v.get("intrusivas"):
        scripts += [s for c in checks for s in c.intrusive_scripts]
    sargs = ["ldap.maxobjects=3", "snmp-brute.communitiesdb=" + str(_communities())] if v.get("credenciales") \
        else ["ldap.maxobjects=3"]
    dom = (v.get("dominio") or "").strip()
    if dom and re.match(r"^[A-Za-z0-9.-]+$", dom) and any(c.id == "dns" for c in checks):
        scripts.append("dns-zone-transfer")
        sargs.append(f"dns-zone-transfer.domain={dom}")
    extra_p = (v.get("puertos_extra") or "").replace(" ", "")
    ports = ",".join(filter(None, ["T:" + ",".join(map(str, tcp)) if tcp else "",
                                   "U:" + ",".join(map(str, udp)) if udp else "", extra_p]))
    args = ["-Pn", "-sV", "--version-light", "-p", ports, "--open", "--script", ",".join(dict.fromkeys(scripts)),
            "--script-args", ",".join(sargs), "-" + (v.get("tiempo") or "T4")]
    args = (["-sS", "-sU"] if udp else ["-sS"]) + args
    return args, scripts


def _communities() -> Path:
    """Lista corta de comunidades SNMP de fábrica (no un diccionario de fuerza bruta)."""
    from ..core import paths
    f = paths.APP_DIR / "opsdeck" / "datos" / "snmp_comunidades.txt"
    return f


def _hosts_from_scan() -> list[str]:
    scans = escaneos()
    if not scans:
        return []
    return [h.ip for h in nmapxml.parse(scans[0]).up()]


def run_checks(ctx: Context, t: list[str], v: dict, d: Path, checks: list[Check]) -> tuple[list[Finding], list, Optional[int]]:
    """Lanza las comprobaciones sobre los objetivos (argumentos de nmap). (hallazgos, filas, rc); rc None = error."""
    args, scripts = build_nmap(v, checks)
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN)
    if err:
        ctx.out.error(err)
        return [], [], None
    out = d / "servicios"
    cmdline = ["nmap", *args, *extra, "-oA", str(out), "--stats-every", "30s", *t]
    tooling.show_cmd(ctx, cmdline)
    rc, _ = stream(ctx, cmdline, accion="exposicion_revisar", objetivo=" ".join(t)[:200],
                   detalle=",".join(c.id for c in checks), keep=15)
    scan = nmapxml.parse(out.with_suffix(".xml"))
    findings: list[Finding] = []
    rows = []
    for h in scan.up():
        hf = analyze_host_scripts(h.ip, h.scripts)
        for p in h.open_ports():
            pf = analyze(h.ip, p, h.scripts)
            if p.port == 9200 or p.service == "elasticsearch":
                pf += elastic(h.ip, p.port)
            findings += pf
            if p.scripts or pf:
                rows.append([f"{h.ip}:{p.port}/{p.proto}", p.service or "?", " ".join(x for x in (p.product, p.version) if x)[:30],
                             "; ".join(f"[{f.severidad}] {f.titulo}" for f in pf)[:90] or "sin hallazgos"])
        findings += hf
    seen, uniq = set(), []                  # SMB puede salir por puerto y por equipo
    for f in findings:
        k = (f.objetivo.split(":")[0], f.tipo, f.titulo)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq, rows, rc


def revisar(ctx: Context, v: dict) -> bool:
    text = (v.get("objetivo") or "").strip()
    if text:
        if not scope.gate(ctx, text, v, "exposicion"):
            return False
        t = _targets(ctx, text)
        if not t:
            return False
        label = text.replace("/", "_")[:40]
    else:
        t = _hosts_from_scan()
        if not t:
            ctx.out.error("Indica un objetivo o haz antes un «Escaneo de red › Escanear».")
            return False
        if not scope.gate(ctx, " ".join(t), v, "exposicion"):
            return False
        ctx.out.info(f"Equipos del último escaneo: {len(t)}")
        label = "ultimo_escaneo"
    checks = _selected(v)
    if not checks:
        ctx.out.error("Elige qué servicios comprobar")
        return False
    d = results.new_dir("exposicion", label)
    ctx.out.info(f"Comprobando {len(checks)} tipos de servicio (TCP{' y UDP' if v.get('udp', True) else ''}); s = detener...")
    findings, rows, rc = run_checks(ctx, t, v, d, checks)
    if rc is None:
        return False
    if not rows:
        ctx.out.info("Ninguno de esos servicios está abierto en los objetivos.")
        return rc == 0
    ctx.out.title(f"{len(rows)} servicios comprobados")
    ctx.out.table(["Servicio", "Tipo", "Producto", "Resultado"], rows)
    real = [f for f in findings if f.severidad != "INFO"]
    if real:
        ctx.out.title(f"Hallazgos ({len(real)})")
        for f in sorted(real, key=lambda f: (recomendacion.ORDEN.get(f.severidad, 9), f.objetivo)):
            ctx.out.check(False, f"[{f.severidad}] {f.objetivo}  {f.titulo}")
    else:
        ctx.out.ok("Ningún servicio con las debilidades típicas.")
    results.write(d / "hallazgos.json", recomendacion.to_json(findings))
    audit.record("exposicion_resultado", label, "OK", f"servicios={len(rows)} hallazgos={len(real)}")
    recomendacion.render(ctx, real)
    return True


def leak_checks(ctx: Context, t: list[str], v: dict, d: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    rows: dict = {}
    if v.get("icmp", True):
        out = d / "icmp_timestamp"
        stream(ctx, ["nmap", "-sn", "-PP", "-n", "--disable-arp-ping", "--reason", "-oA", str(out), *t],
               accion="fugas_icmp", objetivo=" ".join(t)[:200], show=False)
        for host in _xml_hosts(out.with_suffix(".xml")):
            if host["reason"] == "timestamp-reply":
                rows.setdefault(host["ip"], ["-", "-"])[0] = "responde"
                findings.append(Finding(host["ip"], "BAJO", "Responde a ICMP timestamp (revela la hora del sistema)",
                                        "icmp_timestamp"))
    if v.get("tcp", True):
        out = d / "tcp_timestamp"
        ctx.out.info("Detectando marcas de tiempo TCP (detección de sistema operativo, -O)...")
        stream(ctx, ["nmap", "-O", "-n", "-Pn", "--osscan-limit", "-T4", "--top-ports", "50", "-oA", str(out), *t],
               accion="fugas_tcp", objetivo=" ".join(t)[:200], show=False)
        for host in _xml_hosts(out.with_suffix(".xml")):
            if host.get("uptime"):
                dias = int(host["uptime"]) // 86400
                rows.setdefault(host["ip"], ["-", "-"])[1] = f"sí ({dias} d encendido)"
                findings.append(Finding(host["ip"], "BAJO", f"Marcas de tiempo TCP activas (revelan ~{dias} días encendido)",
                                        "tcp_timestamp"))
    return findings, rows


def fugas(ctx: Context, v: dict) -> bool:
    """Marcas de tiempo ICMP (tipo 13) y TCP: lo que más se repite en los informes, ahora verificable."""
    text = (v.get("objetivo") or "").strip()
    t = _targets(ctx, text) if text else _hosts_from_scan()
    if not t:
        if not text:
            ctx.out.error("Indica un objetivo o haz antes un «Escaneo de red › Escanear».")
        return False
    if not scope.gate(ctx, text or " ".join(t), v, "fugas"):
        return False
    d = results.new_dir("exposicion", "fugas_" + (text.replace("/", "_")[:30] or "ultimo_escaneo"))
    findings, rows = leak_checks(ctx, t, v, d)
    if not rows:
        ctx.out.ok("Ningún equipo revela la hora por ICMP ni el tiempo encendido por TCP.")
        return True
    ctx.out.table(["Equipo", "ICMP timestamp", "Marcas de tiempo TCP"], [[ip, *r] for ip, r in sorted(rows.items())])
    results.write(d / "hallazgos.json", recomendacion.to_json(findings))
    audit.record("fugas_resultado", text or "ultimo_escaneo", "OK", f"{len(findings)} hallazgos")
    recomendacion.render(ctx, findings)
    return True


def _xml_hosts(path: Path) -> list[dict]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    out = []
    for h in root.findall("host"):
        st = h.find("status")
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "")
        up = h.find("uptime")
        out.append({"ip": ip, "estado": st.get("state") if st is not None else "",
                    "reason": st.get("reason", "") if st is not None else "",
                    "uptime": up.get("seconds") if up is not None else ""})
    return out


BROADCAST = ["broadcast-dns-service-discovery", "broadcast-upnp-info", "broadcast-netbios-master-browser",
             "broadcast-dhcp-discover", "broadcast-wsdd-discover", "broadcast-ms-sql-discover", "broadcast-pim-discovery",
             "broadcast-igmp-discovery"]


def difusion(ctx: Context, v: dict) -> bool:
    iface = (v.get("interfaz") or "").strip()
    if iface and not re.match(r"^[A-Za-z0-9_.:-]{1,20}$", iface):
        ctx.out.error("Interfaz no válida")
        return False
    d = results.new_dir("exposicion", "difusion")
    out = d / "difusion"
    args = ["nmap", "-sn", "--script", ",".join(BROADCAST), "--script-args", f"timeout={tooling.int_in(v.get('segundos'), 10, 3, 120)}s",
            "-oA", str(out)] + (["-e", iface] if iface else [])
    tooling.show_cmd(ctx, args)
    stream(ctx, args, accion="exposicion_difusion", objetivo=iface or "red local", keep=0, show=False)
    try:
        root = ET.parse(out.with_suffix(".xml")).getroot()
    except (ET.ParseError, OSError):
        ctx.out.error("nmap no generó resultados (¿root? ¿interfaz?)")
        return False
    findings = []
    shown = False
    for s in root.iter("script"):
        sid, txt = s.get("id", ""), s.get("output", "").strip()
        if not txt:
            continue
        shown = True
        ctx.out.title(sid)
        for l in txt.splitlines()[:25]:
            ctx.out.line("  " + l)
        if sid == "broadcast-dns-service-discovery":
            ips = sorted(set(re.findall(r"^\s{2}(\d+\.\d+\.\d+\.\d+)", txt, re.M)))
            findings.append(Finding(", ".join(ips[:6]) or "red local", "BAJO",
                                    f"Equipos que anuncian servicios por mDNS: {len(ips)}", "difusion"))
        elif sid == "broadcast-upnp-info":
            findings.append(Finding("red local", "BAJO", "Dispositivos UPnP anunciándose en la red", "upnp"))
        elif sid == "broadcast-dhcp-discover":
            servers = sorted(set(re.findall(r"Server Identifier: (\S+)", txt)))
            if len(servers) > 1:
                findings.append(Finding(", ".join(servers), "ALTO", f"Varios servidores DHCP responden ({len(servers)}): "
                                        "¿uno no autorizado?", "servicio_info"))
        elif sid == "broadcast-netbios-master-browser":
            findings.append(Finding("red local", "BAJO", "NetBIOS activo (exploradores maestros)", "difusion"))
    if not shown:
        ctx.out.ok("Nada se anuncia por difusión en esta red (o la interfaz no es la correcta).")
    ctx.out.info("LLMNR y NBT-NS se ven mejor escuchando: «Tráfico de red › Descubrimiento pasivo».")
    recomendacion.render(ctx, findings)
    audit.record("exposicion_difusion", iface or "red", "OK", f"{len(findings)} hallazgos")
    return True


class Exposicion(Module):
    full = True
    id = "exposicion"
    name = "Servicios expuestos"
    category = "Ciberseguridad"
    summary = "RDP/NLA, iSCSI, SNMP, NFS, LDAP, DNS, NTP, BBDD, Docker, IPMI, VNC... y fugas ICMP/TCP"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    help = """\
# Servicios expuestos

> Solo contra sistemas propios o con autorización por escrito.

**Comprobar servicios**: para cada servicio abierto confirma la debilidad típica que reportan Nessus
y OpenVAS, con scripts de nmap que solo preguntan (no explotan):

| Servicio | Qué se comprueba |
|---|---|
| RDP | NLA no obligatorio, seguridad nativa con cifrado débil (intermediario) |
| SMB / NetBIOS | SMBv1, firma no obligatoria, nombre NetBIOS |
| iSCSI | destinos sin autenticación |
| SNMP | comunidad «public», datos expuestos |
| NFS / RPC | exportaciones a cualquiera |
| LDAP | consultas anónimas, LDAP sin TLS |
| DNS | recursión abierta, transferencia de zona (indica el dominio) |
| NTP | monlist (amplificación) |
| FTP / TFTP | acceso anónimo, ficheros accesibles |
| SQL Server, MySQL, Redis, MongoDB, Memcached, Elasticsearch | acceso sin autenticación |
| Docker | API 2375 sin TLS (control de root) |
| VNC, X11, MQTT, rsync, RMI | acceso sin contraseña |
| IPMI | cifrado 0, exposición de hashes (RAKP) |
| UPnP, SMTP, AJP, WinRM, Telnet | anuncios, VRFY/EXPN, Ghostcat, servicios en claro |

Sin objetivo usa los equipos del último escaneo. Elige **todos** o un servicio concreto.

**Opciones avanzadas**: incluir o no UDP, puertos adicionales, dominio para probar la transferencia
de zona, velocidad, opciones de nmap y dos grupos que piden confirmación:
- **Credenciales por defecto**: usuario `sa`/`root` sin contraseña en SQL Server y MySQL y una lista
  corta de comunidades SNMP de fábrica. Puede generar alertas o bloquear cuentas.
- **Pruebas intrusivas**: relay SMTP abierto (intenta un envío sin terminarlo).

**Fugas de información de red**: qué equipos responden a **ICMP timestamp** y cuáles tienen
**marcas de tiempo TCP** (revelan cuánto llevan encendidos). Son dos de los hallazgos más repetidos.

**Protocolos de difusión**: lo que se anuncia en la red local (mDNS, UPnP, NetBIOS, WS-Discovery,
DHCP —detecta servidores DHCP no autorizados—, SQL Server).
"""

    def actions(self):
        A = dict(required=False, advanced=True)
        ok = scope.ok_param()
        obj = Param("objetivo", "Objetivo (vacío = equipos del último escaneo)", required=False, suggest=_subnets,
                    help="IP, red, rango, varios separados por espacio o fichero")

        def confirm(v):
            parts = []
            if v.get("credenciales"):
                parts.append("intentar credenciales de fábrica (puede bloquear cuentas o generar alertas)")
            if v.get("intrusivas"):
                parts.append("probar el relay SMTP")
            return ("Se van a " + " y ".join(parts) + ". ¿Tienes autorización?") if parts else ""

        return [
            Action("revisar", "Comprobar servicios", revisar, params=[
                obj, Param("servicios", "Servicios", "choice", "todos",
                           choices=[("todos", "Todos")] + [(c.id, c.nombre) for c in CHECKS]), ok,
                Param("udp", "Incluir UDP (SNMP, NTP, IPMI, TFTP, UPnP, NetBIOS)", "bool", True, **A),
                Param("puertos_extra", "Puertos adicionales", **A, help="Ej.: T:8022,U:1161 (servicios en puertos no estándar)"),
                Param("dominio", "Dominio para probar la transferencia de zona (DNS)", **A, help="Ej.: ejemplo.local"),
                Param("credenciales", "Probar credenciales por defecto (SQL sin contraseña, comunidades SNMP)",
                      "bool", False, **A),
                Param("intrusivas", "Pruebas intrusivas (relay SMTP abierto)", "bool", False, **A),
                Param("tiempo", "Velocidad", "choice", "T4", choices=[("T2", "T2 educado"), ("T3", "T3 normal"),
                                                                      ("T4", "T4 rápido")], **A),
                tooling.p_extra("nmap", "--max-retries 1")], confirm=confirm),
            Action("fugas", "Fugas de información de red (ICMP/TCP timestamp)", fugas, params=[
                obj, ok, Param("icmp", "ICMP timestamp", "bool", True, **A),
                Param("tcp", "Marcas de tiempo TCP (usa -O)", "bool", True, **A)]),
            Action("difusion", "Protocolos de difusión en la red local", difusion, params=[
                Param("interfaz", "Interfaz (vacío = la predeterminada)", required=False),
                Param("segundos", "Tiempo de escucha por protocolo (s)", "int", 10, **A)]),
        ]
