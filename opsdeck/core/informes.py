"""Lectura de informes de escáneres de vulnerabilidades (Nessus y OpenVAS/Greenbone).

Formatos: .nessus (XML), XML de OpenVAS/GVM, CSV de Nessus y de OpenVAS y, como último recurso, el
PDF de ambos (vía pdftotext; Nessus «por equipo» y «por plugin», OpenVAS «resultados por equipo»).
Todo se normaliza a una lista de Item, y cada Item se asocia a la comprobación de opsdeck que lo
puede volver a verificar (TLS, SSH, SMB, RDP, servicios, web, nuclei...)."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import system

SEV_NESSUS = {"4": "CRÍTICO", "3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFO"}
SEV_WORD = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO", "none": "INFO",
            "log": "INFO", "informational": "INFO"}
IP = r"\d{1,3}(?:\.\d{1,3}){3}"


@dataclass
class Item:
    host: str
    puerto: Optional[int]
    proto: str
    severidad: str
    id: str
    nombre: str
    cvss: str = ""
    fuente: str = ""
    salida: str = ""
    cves: list[str] = field(default_factory=list)

    @property
    def objetivo(self) -> str:
        return f"{self.host}:{self.puerto}" if self.puerto else self.host


def _sev_cvss(c: str) -> str:
    try:
        x = float(c)
    except (TypeError, ValueError):
        return "INFO"
    return "CRÍTICO" if x >= 9 else "ALTO" if x >= 7 else "MEDIO" if x >= 4 else "BAJO" if x > 0 else "INFO"


# ---------------------------------------------------------------- formatos

def parse_nessus_xml(root: ET.Element) -> list[Item]:
    out = []
    for rh in root.iter("ReportHost"):
        host = rh.get("name", "")
        for tag in rh.iter("tag"):
            if tag.get("name") == "host-ip" and tag.text:
                host = tag.text.strip()
        for ri in rh.findall("ReportItem"):
            port = int(ri.get("port", "0") or 0) or None
            out.append(Item(host, port, ri.get("protocol", "tcp"), SEV_NESSUS.get(ri.get("severity", "0"), "INFO"),
                            ri.get("pluginID", ""), ri.get("pluginName", ""),
                            (ri.findtext("cvss3_base_score") or ri.findtext("cvss_base_score") or ""), "nessus",
                            (ri.findtext("plugin_output") or "")[:600], [c.text for c in ri.findall("cve") if c.text]))
    return out


def parse_openvas_xml(root: ET.Element) -> list[Item]:
    out = []
    for r in root.iter("result"):
        nvt = r.find("nvt")
        if nvt is None:
            continue
        host_el = r.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        port_txt = r.findtext("port") or ""
        m = re.match(r"(\d+)/(\w+)", port_txt)
        sev = r.findtext("threat") or ""
        cvss = r.findtext("severity") or nvt.findtext("cvss_base") or ""
        cves = [ref.get("id") for ref in nvt.iter("ref") if ref.get("type") == "cve"]
        out.append(Item(host, int(m.group(1)) if m else None, m.group(2) if m else port_txt.split("/")[-1],
                        SEV_WORD.get(sev.lower(), _sev_cvss(cvss)), nvt.get("oid", ""), nvt.findtext("name") or "",
                        cvss, "openvas", (r.findtext("description") or "")[:600], cves))
    return out


def parse_csv(text: str) -> list[Item]:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        return []
    keys = {k.lower().strip(): k for k in rows[0].keys() if k}
    out = []
    if "plugin id" in keys:                         # Nessus
        for r in rows:
            g = lambda k: (r.get(keys.get(k, ""), "") or "").strip()
            port = g("port")
            risk = g("risk") or g("severity")
            out.append(Item(g("host") or g("ip address"), int(port) if port.isdigit() and port != "0" else None,
                            g("protocol") or "tcp", SEV_WORD.get(risk.lower(), _sev_cvss(g("cvss v3.0 base score")
                                                                                       or g("cvss v2.0 base score"))),
                            g("plugin id"), g("name"), g("cvss v3.0 base score") or g("cvss v2.0 base score") or g("cvss"),
                            "nessus", g("plugin output")[:600], [c for c in re.split(r"[,\s]+", g("cve")) if c]))
    elif "nvt name" in keys or "nvt oid" in keys:   # OpenVAS
        for r in rows:
            g = lambda k: (r.get(keys.get(k, ""), "") or "").strip()
            port = g("port")
            out.append(Item(g("ip"), int(port) if port.isdigit() else None, g("port protocol") or "tcp",
                            SEV_WORD.get(g("severity").lower(), _sev_cvss(g("cvss"))), g("nvt oid"), g("nvt name"),
                            g("cvss"), "openvas", g("specific result")[:600],
                            [c for c in re.split(r"[,\s]+", g("cves")) if c]))
    return out


def parse_pdf_text(text: str) -> list[Item]:
    # Ligaduras de LaTeX: pdftotext las saca como U+FB0x o como caracteres de control (que además
    # str.splitlines() toma por saltos de línea y cortarían los nombres).
    for a, b in (("\ufb01", "fi"), ("\ufb02", "fl"), ("\ufb00", "ff"), ("\ufb03", "ffi"), ("\ufb04", "ffl"),
                 ("\x1c", "fi"), ("\x1d", "fl"), ("\x1b", "ff"), ("\x1e", "ffi"), ("\x1f", "ffl")):
        text = text.replace(a, b)
    if "NVT:" in text and re.search(r"Results per Host", text):
        return _pdf_openvas(text)
    if re.search(r"^\d{4,6} \(\d+\) - ", text, re.M):
        return _pdf_nessus_plugin(text)
    return _pdf_nessus_host(text)


def _pdf_openvas(text: str) -> list[Item]:
    out, host, port, proto, sev, cvss = [], "", None, "", "", ""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(rf"^2\.\d+\s+({IP})\s*$", s)
        if m:
            host = m.group(1)
            continue
        m = re.match(r"^2\.\d+\.\d+\s+(High|Medium|Low|Log)\s+(\S+)\s*$", s)
        if m:
            pp = m.group(2)
            mm = re.match(r"(\d+)/(\w+)", pp)
            port, proto = (int(mm.group(1)), mm.group(2)) if mm else (None, pp.split("/")[-1])
            continue
        m = re.match(r"^(High|Medium|Low|Log) \(CVSS: ([\d.]+)\)", s)
        if m:
            sev, cvss = SEV_WORD[m.group(1).lower()], m.group(2)
            continue
        m = re.match(r"^NVT: (.+)$", s)
        if m and host:
            out.append(Item(host, port, proto, sev or "INFO", "", m.group(1).strip(), cvss, "openvas-pdf"))
    return out


def _pdf_nessus_plugin(text: str) -> list[Item]:
    out, pid, name, sev, cvss = [], "", "", "", ""
    seen = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        m = re.match(r"^(\d{4,6}) \(\d+\) - (.+?)(\s{2,}\d+)?$", s)
        if m:
            if m.group(1) != pid:
                pid, name, sev, cvss = m.group(1), m.group(2).strip(), "", ""
            continue
        if s == "Risk Factor":
            nxt = next((l.strip() for l in lines[i + 1:i + 4] if l.strip()), "")
            sev = SEV_WORD.get(nxt.lower(), sev)
            continue
        if s in ("CVSS v3.0 Base Score", "CVSS v2.0 Base Score") and not cvss:
            nxt = next((l.strip() for l in lines[i + 1:i + 4] if l.strip()), "")
            cvss = nxt.split()[0] if nxt else ""
            continue
        m = re.match(rf"^({IP}) \((tcp|udp)/(\d+)/?([^)]*)\)\s*$", s)
        if m and pid:
            key = (pid, m.group(1), m.group(3))
            if key not in seen:
                seen.add(key)
                out.append(Item(m.group(1), int(m.group(3)) or None, m.group(2), sev or _sev_cvss(cvss) or "INFO",
                                pid, name, cvss, "nessus-pdf"))
    return out


def _pdf_nessus_host(text: str) -> list[Item]:
    out, host, pending = [], "", None
    row = re.compile(r"^\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d{4,6})\s+(.+?)\s*$")
    for line in text.splitlines():
        m = re.match(rf"^\s{{8,}}({IP})\s*$", line)
        if m:
            host = m.group(1)
            continue
        m = row.match(line)
        if m and host:
            out.append(Item(host, None, "", SEV_WORD[m.group(1).lower()], m.group(5), m.group(6), m.group(2), "nessus-pdf"))
            pending = None
            continue
        m = re.match(r"^\s*(?:(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+)?(\S+)\s+\S+\s+\S+\s+(\d{4,6})\s*$", line)
        if m and host:
            pending = (m.group(2), m.group(1))
            continue
        m = re.match(r"^\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s{3,}([A-Za-z].+?)\s*$", line)
        if m and host and not re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", m.group(2)):
            pid, cv = pending or ("", "")
            out.append(Item(host, None, "", SEV_WORD[m.group(1).lower()], pid, m.group(2), cv, "nessus-pdf"))
            pending = None
    return out


def load(path: Path) -> tuple[list[Item], str]:
    """Lee un informe. Devuelve (items, formato) o ([], mensaje de error)."""
    if not path.is_file():
        return [], f"No existe {path}"
    head = path.read_bytes()[:2048]
    if head.startswith(b"%PDF"):
        if not system.has_cmd("pdftotext"):
            return [], "Para leer PDF hace falta pdftotext (paquete poppler-utils). Mejor: exporta el informe en .nessus o XML."
        r = system.run(["pdftotext", "-layout", str(path), "-"], timeout=300)
        items = parse_pdf_text(r.out)
        return items, "pdf" if items else "PDF sin resultados reconocibles (exporta en .nessus/XML/CSV)"
    text = path.read_text(errors="replace")
    if text.lstrip().startswith("<"):
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            return [], f"XML mal formado: {e}"
        if root.tag.startswith("NessusClientData") or root.find(".//ReportHost") is not None:
            return parse_nessus_xml(root), "nessus"
        if root.find(".//result/nvt") is not None:
            return parse_openvas_xml(root), "openvas"
        return [], "XML que no es de Nessus ni de OpenVAS"
    items = parse_csv(text)
    return (items, "csv") if items else ([], "Formato no reconocido (usa .nessus, XML de OpenVAS, CSV o PDF)")


def save(items: list[Item], path: Path) -> None:
    path.write_text(json.dumps([asdict(i) for i in items], ensure_ascii=False, indent=0) + "\n", encoding="utf-8")


def read(path: Path) -> list[Item]:
    try:
        return [Item(**d) for d in json.loads(path.read_text(encoding="utf-8"))]
    except (OSError, json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------- de hallazgo del informe a comprobación de opsdeck

# (patrón sobre el nombre, comprobación, tipos de hallazgo de opsdeck que lo confirman, texto en hallazgos web)
MAPA = [
    (r"SSL Version 2 and 3|SSLv[23]|POODLE|SSLv3 Protocol", "tls", {"tls_ssl", "tls_vuln"}, ""),
    (r"TLS Version 1\.[01]|TLSv1\.[01]|Deprecated TLS", "tls", {"tls_obsoleto"}, ""),
    (r"SWEET32|Medium Strength Cipher|64-bit block", "tls", {"tls_sweet32"}, ""),
    (r"RC4|Bar Mitzvah", "tls", {"tls_rc4"}, ""),
    (r"Anonymous'? Cipher", "tls", {"tls_anon"}, ""),
    (r"(Weak|Vulnerable) Cipher Suites|NULL Cipher|EXPORT", "tls", {"tls_sweet32", "tls_rc4", "tls_anon", "tls_null"}, ""),
    (r"Self-Signed", "tls", {"cert_autofirmado"}, ""),
    (r"Cannot Be Trusted|Untrusted|Chain.*Not Trusted", "tls", {"cert_no_confianza", "cert_autofirmado"}, ""),
    (r"Wrong Hostname|commonName.*Mismatch", "tls", {"cert_nombre"}, ""),
    (r"Certificate Expir|Certificate Expired|Expiring Soon|Certicate Expired|Certificate.*Expired", "tls",
     {"cert_caducado", "cert_pronto"}, ""),
    (r"Weak Hashing|Weak Signature", "tls", {"tls_firma_debil"}, ""),
    (r"less than 2048|RSA keys", "tls", {"tls_clave_corta"}, ""),
    (r"Renegotiation", "tls", {"tls_renegociacion"}, ""),
    (r"Heartbleed|CCS Injection", "tls", {"tls_vuln"}, ""),
    (r"Diffie-Hellman|Logjam|DHE Key", "tls", {"tls_dh_debil"}, ""),
    (r"Terrapin", "ssh", {"ssh_terrapin"}, ""),
    (r"SSH.*(Key Exchange|KEX)|(Key Exchange|KEX).*SSH", "ssh", {"ssh_kex"}, ""),
    (r"SSH.*(CBC|Encryption Algorithm)|(CBC|Encryption Algorithm).*SSH", "ssh", {"ssh_cifrado"}, ""),
    (r"SSH.*\b(MAC|HMAC)\b|\b(MAC|HMAC)\b.*SSH", "ssh", {"ssh_mac"}, ""),
    (r"Host Key Algorithm|SSH.*Host Key", "ssh", {"ssh_hostkey"}, ""),
    (r"SSH Password Authentication", "ssh", {"ssh_password"}, ""),
    (r"SMB Signing|Signing not required", "smb", {"smb_sin_firma"}, ""),
    (r"SMBv1|SMB.*Version 1|Protocol Version 1 Enabled", "smb", {"smbv1"}, ""),
    (r"Network Level Authentication|\(NLA\)", "rdp", {"rdp_nla"}, ""),
    (r"Remote Desktop.*Man-in-the-Middle|Terminal Services Encryption", "rdp", {"rdp_cifrado", "rdp_nla"}, ""),
    (r"ICMP Timestamp", "icmp", {"icmp_timestamp"}, ""),
    (r"TCP Timestamps", "tcp", {"tcp_timestamp"}, ""),
    (r"iSCSI.*Unauthenticated", "exposicion:iscsi", {"iscsi_sin_auth"}, ""),
    (r"SNMP.*(Community|Default|public|Agent Default)", "exposicion:snmp", {"snmp_comunidad"}, ""),
    (r"NFS.*(Export|Share)", "exposicion:nfs", {"nfs_export"}, ""),
    (r"LDAP.*(Anonymous|NULL BIND|Crafted Search)", "exposicion:ldap", {"ldap_anonimo"}, ""),
    (r"DNS.*Recursi", "exposicion:dns", {"dns_recursion"}, ""),
    (r"Zone Transfer|AXFR", "exposicion:dns", {"dns_axfr"}, ""),
    (r"monlist|NTP.*Mode 6", "exposicion:ntp", {"ntp_monlist"}, ""),
    (r"Anonymous FTP", "exposicion:ftp", {"ftp_anonimo"}, ""),
    (r"TFTP", "exposicion:tftp", {"tftp_abierto"}, ""),
    (r"Redis.*(Unauth|No Auth|without|Unprotected|Password)", "exposicion:redis", {"bd_sin_auth"}, ""),
    (r"MongoDB.*(Unauth|No Auth|without|Unprotected|Password)", "exposicion:mongodb", {"bd_sin_auth"}, ""),
    (r"Memcached", "exposicion:memcached", {"bd_sin_auth"}, ""),
    (r"Elasticsearch.*(Unauth|without|Unprotected)", "exposicion:elastic", {"bd_sin_auth"}, ""),
    (r"Docker.*(Remote API|Unprotected|Unauth|Daemon)", "exposicion:docker", {"docker_api"}, ""),
    (r"VNC.*(No Auth|without|None|Unauth)", "exposicion:vnc", {"vnc_sin_auth"}, ""),
    (r"IPMI.*Cipher.*(Zero|0)", "exposicion:ipmi", {"ipmi_cifrado0"}, ""),
    (r"IPMI", "exposicion:ipmi", {"ipmi_expuesto", "ipmi_cifrado0"}, ""),
    (r"Open Relay", "exposicion:smtp", {"smtp_relay"}, ""),
    (r"VRFY|EXPN", "exposicion:smtp", {"smtp_vrfy"}, ""),
    (r"LLMNR|mDNS|NBT-NS|NetBIOS Name", "difusion", set(), ""),
    (r"DCE/RPC|MSRPC|RPC Services Enumeration", "manual", set(), ""),
    (r"HSTS|Strict Transport", "web", set(), r"strict-transport-security|HSTS"),
    (r"Cookie.*(Secure|HttpOnly|SameSite)|'(Secure|HttpOnly)' Cookie", "web", set(), r"Cookie"),
    (r"Cleartext Transmission|Password.*(HTTP|clear)", "web", set(), r"contraseña servido por HTTP|sin redirigir"),
    (r"HTTP Methods|HTTP TRACE|TRACE Method|WebDAV", "web", set(), r"Métodos HTTP|TRACE"),
    (r"Sensitive File|Home Folder|Backup File|\.git|phpinfo|server-status|Information Disclosure \(HTTP\)",
     "web_ficheros", set(), r"."),
    (r"Default (Install )?Page|Unconfigured", "web", set(), r"Página por defecto"),
    (r"Directory Listing|Browsable", "web", set(), r"Listado de directorio"),
    (r"End of Life|EOL|Unsupported", "manual", set(), ""),
    (r"(<|before) ?\d|Multiple Vulnerabilities|CVE-\d{4}-\d+|Vulnerabilit", "nuclei", set(), ""),
]

DONDE = {
    "tls": ("TLS y certificados › Revisar TLS", "tls revisar"),
    "ssh": ("Auditoría SSH › Revisar SSH", "ssh revisar"),
    "smb": ("SMB y Windows › Seguridad SMB", "smb seguridad"),
    "rdp": ("Servicios expuestos › Comprobar (RDP)", "exposicion revisar --servicios rdp"),
    "icmp": ("Servicios expuestos › Fugas de información", "exposicion fugas"),
    "tcp": ("Servicios expuestos › Fugas de información", "exposicion fugas"),
    "difusion": ("Tráfico de red › Descubrimiento pasivo", "trafico pasivo"),
    "web": ("Web y TLS › Revisar una web", "web revisar"),
    "web_ficheros": ("Web y TLS › Ficheros y rutas sensibles", "web ficheros"),
    "nuclei": ("Vulnerabilidades (nuclei) › Análisis dirigido / Analizar", "nuclei analizar"),
    "manual": ("Revisión manual / otra herramienta", ""),
}


def classify(it: Item) -> tuple[str, set, str]:
    for pat, check, tipos, txt in MAPA:
        if re.search(pat, it.nombre, re.I):
            return check, tipos, txt
    return "manual", set(), ""


def donde(check: str) -> tuple[str, str]:
    if check.startswith("exposicion:"):
        svc = check.split(":", 1)[1]
        return (f"Servicios expuestos › Comprobar ({svc})", f"exposicion revisar --servicios {svc}")
    return DONDE.get(check, ("Revisión manual", ""))
