"""TLS y certificados de cualquier servicio (no solo webs): versiones, cifrados y certificado.

Comprueba lo que más aparece en los informes de Nessus y OpenVAS: SSL 2/3, TLS 1.0/1.1, RC4,
3DES (SWEET32), cifrados anónimos, NULL y EXPORT, firma débil del certificado, claves cortas,
certificados autofirmados, no confiables, caducados o con el nombre equivocado, parámetros DH
débiles, renegociación insegura y Heartbleed/POODLE/CCS. Sirve para webs, RDP, LDAPS, correo
(también con STARTTLS), bases de datos, iLO/iDRAC y cualquier puerto con TLS.

Motor: nmap (siempre) y, si está instalado, sslscan para la renegociación y la compresión."""

from __future__ import annotations

import re
import socket
import ssl
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..core import audit, nmapxml, recomendacion, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from ..core.recomendacion import Finding
from .escaneo import TARGET_RE, _subnets, ultimo

# Puertos que suelen llevar TLS directo o STARTTLS (nmap negocia STARTTLS en SMTP, POP3, IMAP, FTP, LDAP,
# XMPP, PostgreSQL, MySQL...). Se usan cuando el objetivo no indica puerto.
TLS_PORTS = [443, 8443, 636, 3269, 993, 995, 465, 587, 25, 389, 3389, 5986, 8006, 9443, 10443, 4443, 990, 5061,
             6443, 2376, 5432, 3306, 1433, 21, 110, 143, 8834, 9392, 5001, 7443]
SCRIPTS = "ssl-enum-ciphers,ssl-cert,ssl-dh-params,sslv2,ssl-heartbleed,ssl-poodle,ssl-ccs-injection"
DIRECT_TLS = {443, 8443, 636, 3269, 993, 995, 465, 3389, 5986, 8006, 9443, 10443, 4443, 990, 5061, 6443, 2376,
              8834, 9392, 5001, 7443}


# ---------------------------------------------------------------- interpretación

def parse_ciphers(text: str) -> dict:
    """Salida de ssl-enum-ciphers -> {versiones: {ver: [cifrados]}, avisos: [...], nota: 'A'}"""
    out: dict = {"versiones": defaultdict(list), "avisos": [], "nota": ""}
    ver = None
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^(SSLv2|SSLv3|TLSv1\.[0-3]):\s*$", line)
        if m:
            ver, section = m.group(1), ""
            out["versiones"][ver]
            continue
        if line.endswith(":") and line[:-1] in ("ciphers", "compressors", "warnings", "cipher preference"):
            section = line[:-1]
            continue
        if line.startswith("least strength:"):
            out["nota"] = line.split(":", 1)[1].strip()
            continue
        if section == "ciphers" and ver and line.startswith(("TLS_", "SSL_")):
            out["versiones"][ver].append(line.split()[0])
        elif section == "warnings" and line:
            out["avisos"].append(line)
    out["versiones"] = dict(out["versiones"])
    return out


def parse_cert(text: str) -> dict:
    c: dict = {}
    for key, pat in (("sujeto", r"Subject: (.+)"), ("emisor", r"Issuer: (.+)"), ("tipo_clave", r"Public Key type: (\S+)"),
                     ("bits", r"Public Key bits: (\d+)"), ("firma", r"Signature Algorithm: (\S+)"),
                     ("desde", r"Not valid before:\s*(\S+)"), ("hasta", r"Not valid after:\s*(\S+)"),
                     ("nombres", r"Subject Alternative Name: (.+)")):
        m = re.search(pat, text)
        if m:
            c[key] = m.group(1).strip()
    if not c.get("sujeto") and not c.get("hasta"):
        return {}
    cn = re.search(r"commonName=([^/,\n]+)", c.get("sujeto", ""))
    c["cn"] = cn.group(1).strip() if cn else ""
    if c.get("hasta"):
        try:
            end = datetime.fromisoformat(c["hasta"].replace("Z", "")).replace(tzinfo=None)
            c["dias"] = (end - datetime.now(timezone.utc).replace(tzinfo=None)).days
        except ValueError:
            pass
    return c


def name_matches(name: str, cert: dict) -> bool:
    names = [n.strip()[4:] for n in cert.get("nombres", "").split(",") if n.strip().startswith("DNS:")]
    names += [n.strip()[11:] for n in cert.get("nombres", "").split(",") if n.strip().startswith("IP Address:")]
    if cert.get("cn"):
        names.append(cert["cn"])
    name = name.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == name or (n.startswith("*.") and name.endswith(n[1:]) and name.count(".") == n.count(".")):
            return True
    return False


def trusted(host: str, port: int, sni: str) -> Optional[str]:
    """None si es de confianza; si no, el motivo. '' si no se pudo comprobar."""
    try:
        with socket.create_connection((host, port), timeout=6) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=sni or host) as _:
            return None
    except ssl.SSLCertVerificationError as e:
        return e.verify_message or "no verificable"
    except (ssl.SSLError, OSError, ValueError):
        return ""


def analyze_port(ip: str, name: str, p: nmapxml.Port, check_trust: bool = True, soon_days: int = 30) -> list[Finding]:
    """Hallazgos de TLS de un puerto a partir de los scripts NSE (y de la confianza del certificado)."""
    obj = f"{ip}:{p.port}"
    out: list[Finding] = []
    enum = parse_ciphers(p.scripts.get("ssl-enum-ciphers", ""))
    vers = enum["versiones"]
    allc = [c for cs in vers.values() for c in cs]

    def add(sev, title, tipo, **datos):
        out.append(Finding(obj, sev, title, tipo, datos={"puerto": p.port, **datos}))

    if "SSLv2" in vers or "SSLv2 supported" in p.scripts.get("sslv2", ""):
        add("ALTO", "SSL 2.0 activo", "tls_ssl")
    if "SSLv3" in vers:
        add("ALTO", "SSL 3.0 activo (POODLE)", "tls_ssl")
    old = [v for v in ("TLSv1.0", "TLSv1.1") if v in vers]
    if old:
        add("MEDIO", f"Acepta versiones obsoletas: {', '.join(old)}", "tls_obsoleto")
    if vers and not any(v in vers for v in ("TLSv1.2", "TLSv1.3")):
        add("ALTO", "No admite TLS 1.2 ni 1.3", "tls_obsoleto")
    rc4 = sorted({c for c in allc if "RC4" in c})
    if rc4:
        add("MEDIO", f"Cifrados RC4 (Bar Mitzvah): {len(rc4)}", "tls_rc4", cifrados=rc4)
    tdes = sorted({c for c in allc if "3DES" in c or "DES_CBC" in c or "IDEA" in c})
    if tdes:
        add("ALTO", f"Cifrados de bloque de 64 bits, 3DES/DES (SWEET32): {len(tdes)}", "tls_sweet32", cifrados=tdes)
    anon = sorted({c for c in allc if "_anon_" in c})
    if anon:
        add("MEDIO", f"Cifrados anónimos, sin autenticación del servidor: {len(anon)}", "tls_anon", cifrados=anon)
    null = sorted({c for c in allc if "_NULL_" in c or c.endswith("_NULL") or "EXPORT" in c})
    if null:
        add("ALTO", f"Cifrados NULL o EXPORT: {len(null)}", "tls_null", cifrados=null)
    cert = parse_cert(p.scripts.get("ssl-cert", ""))
    if cert:
        sig = cert.get("firma", "").lower()
        if "md5" in sig or "sha1" in sig:
            add("MEDIO", f"Certificado firmado con algoritmo débil ({cert['firma']})", "tls_firma_debil")
        if cert.get("tipo_clave", "").lower() == "rsa" and cert.get("bits", "").isdigit() and int(cert["bits"]) < 2048:
            add("MEDIO", f"Clave RSA del certificado de {cert['bits']} bits (< 2048)", "tls_clave_corta")
        if "dias" in cert:
            if cert["dias"] < 0:
                add("ALTO", f"Certificado CADUCADO ({cert['hasta'][:10]})", "cert_caducado")
            elif cert["dias"] < soon_days:
                add("MEDIO", f"El certificado caduca en {cert['dias']} días ({cert['hasta'][:10]})", "cert_pronto")
        self_signed = cert.get("sujeto") and cert.get("sujeto") == cert.get("emisor")
        if self_signed:
            add("MEDIO", f"Certificado autofirmado ({cert.get('cn') or cert.get('sujeto', '')[:50]})", "cert_autofirmado")
        if name and not re.match(r"^[\d.:]+$", name) and not name_matches(name, cert):
            add("MEDIO", f"El certificado no corresponde al nombre {name} (es para {cert.get('cn') or '?'})", "cert_nombre")
        if check_trust and not self_signed and p.port in DIRECT_TLS:
            why = trusted(ip, p.port, name if name and not re.match(r"^[\d.:]+$", name) else "")
            if why:
                add("MEDIO", f"Certificado no de confianza ({why})", "cert_no_confianza")
    for w in enum["avisos"]:
        wl = w.lower()
        if "insecure certificate signature" in wl and not any(f.tipo == "tls_firma_debil" for f in out):
            add("MEDIO", "Certificado con firma insegura", "tls_firma_debil")
        elif "key exchange" in wl and "lower strength" in wl:
            add("BAJO", f"Intercambio de claves débil: {w[:80]}", "tls_dh_debil")
    dh = p.scripts.get("ssl-dh-params", "")
    if "VULNERABLE" in dh:
        add("MEDIO", "Parámetros Diffie-Hellman débiles (Logjam / grupo corto)", "tls_dh_debil")
    for sid, title in (("ssl-heartbleed", "Heartbleed (CVE-2014-0160)"), ("ssl-poodle", "POODLE (CVE-2014-3566)"),
                       ("ssl-ccs-injection", "Inyección CCS (CVE-2014-0224)")):
        if "State: VULNERABLE" in p.scripts.get(sid, ""):
            add("CRÍTICO" if sid == "ssl-heartbleed" else "ALTO", f"Vulnerable a {title}", "tls_vuln", id=sid)
    return out


def sslscan_extra(host: str, port: int) -> list[Finding]:
    """Renegociación insegura y compresión TLS (CRIME), solo si sslscan está instalado."""
    if not system.has_cmd("sslscan"):
        return []
    r = system.run(["sslscan", "--no-colour", "--xml=-", "--no-ciphersuites", "--no-cipher-details", "--no-groups",
                    "--no-heartbleed", f"{host}:{port}"], c_locale=True, timeout=120)
    out = []
    try:
        root = ET.fromstring(r.out[r.out.find("<?xml"):] if "<?xml" in r.out else r.out)
    except ET.ParseError:
        return []
    obj = f"{host}:{port}"
    for ren in root.iter("renegotiation"):
        if ren.get("supported") == "1" and ren.get("secure") != "1":
            out.append(Finding(obj, "MEDIO", "Renegociación TLS insegura (CVE-2009-3555)", "tls_renegociacion",
                               datos={"puerto": port}))
        elif ren.get("supported") == "1":
            out.append(Finding(obj, "BAJO", "Acepta renegociación iniciada por el cliente (DoS, CVE-2011-1473)",
                               "tls_renegociacion", datos={"puerto": port}))
    for comp in root.iter("compression"):
        if comp.get("supported") == "1":
            out.append(Finding(obj, "MEDIO", "Compresión TLS activa (CRIME)", "tls_compresion", datos={"puerto": port}))
    return out


# ---------------------------------------------------------------- ejecución

def _split_targets(text: str) -> tuple[dict, list[str]]:
    """«host», «host:puerto», URL, red o fichero -> ({host: {puertos}}, errores)."""
    items = text.split()
    if len(items) == 1 and Path(items[0]).is_file():
        items = [l.strip() for l in Path(items[0]).read_text(errors="replace").splitlines()
                 if l.strip() and not l.startswith("#")]
    out: dict = defaultdict(set)
    bad = []
    for it in items:
        port = None
        if "://" in it:
            from urllib.parse import urlparse
            u = urlparse(it)
            host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
        elif it.startswith("["):
            host, _, rest = it[1:].partition("]")
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
        elif it.count(":") == 1 and it.split(":")[1].isdigit():
            host, port = it.split(":")[0], int(it.split(":")[1])
        else:
            host = it
        if not host or not TARGET_RE.match(host):
            bad.append(it)
            continue
        if port:
            out[host].add(port)
        else:
            out[host]
    return dict(out), bad


def targets_from_scan(scan: nmapxml.Scan) -> dict:
    out: dict = defaultdict(set)
    for h in scan.up():
        for p in h.open_ports():
            if p.proto == "tcp" and (p.is_tls or p.port in TLS_PORTS or "ssl" in p.service or "https" in p.service):
                out[h.ip].add(p.port)
    return dict(out)


def run_checks(ctx: Context, groups: dict, v: dict, d: Path, label: str = "tls") -> tuple[list[Finding], list]:
    """Lanza nmap sobre {host: {puertos}} (sin puertos = los habituales) y devuelve (hallazgos, filas)."""
    by_ports: dict = defaultdict(list)
    for host, ports in groups.items():
        by_ports[tuple(sorted(ports or TLS_PORTS))].append(host)
    findings: list[Finding] = []
    rows = []
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN)
    if err:
        ctx.out.error(err)
        return [], []
    names: dict = {}                       # IP -> nombre con el que se pidió (para comprobar el certificado)
    for host in groups:
        if not re.match(r"^[\d.:/-]+$", host):
            for ip in {str(x[4][0]) for x in _safe_resolve(host)}:
                names.setdefault(ip, host)
    for i, (ports, hosts) in enumerate(by_ports.items(), 1):
        out = d / f"tls_{i}"
        args = ["nmap", "-Pn", "-sV", "--version-light", "-p", ",".join(map(str, ports)), "--open",
                "--script", SCRIPTS, "-T" + (v.get("tiempo") or "4")[-1], "-oA", str(out), *extra, *hosts]
        tooling.show_cmd(ctx, args)
        stream(ctx, args, accion=f"{label}_nmap", objetivo=" ".join(hosts), keep=8)
        scan = nmapxml.parse(out.with_suffix(".xml"))
        for h in scan.up():
            name = names.get(h.ip) or h.name
            for p in h.open_ports():
                if "ssl-enum-ciphers" not in p.scripts and "ssl-cert" not in p.scripts:
                    continue
                f = analyze_port(h.ip, name, p, check_trust=not v.get("sin_confianza"),
                                 soon_days=tooling.int_in(v.get("dias_aviso"), 30, 1, 365))
                if v.get("sslscan", True):
                    f += sslscan_extra(h.ip, p.port)
                findings += f
                enum = parse_ciphers(p.scripts.get("ssl-enum-ciphers", ""))
                cert = parse_cert(p.scripts.get("ssl-cert", ""))
                rows.append([f"{h.ip}:{p.port}", p.service or "?",
                             " ".join(v_.replace("TLSv", "") for v_ in enum["versiones"]) or "?",
                             enum["nota"] or "-", (cert.get("cn") or "-")[:28],
                             str(cert.get("dias", "?")), str(len(f))])
    return findings, rows


def _safe_resolve(name: str):
    try:
        return socket.getaddrinfo(name, None)
    except OSError:
        return []


def show(ctx: Context, findings: list[Finding], rows: list, d: Path) -> None:
    if not rows:
        ctx.out.info("No se encontró ningún servicio con TLS en esos objetivos.")
        return
    ctx.out.title(f"{len(rows)} servicios con TLS")
    ctx.out.table(["Servicio", "Tipo", "Versiones", "Nota", "Certificado (CN)", "Días", "Hallazgos"], rows)
    if findings:
        ctx.out.title("Hallazgos")
        order = recomendacion.ORDEN
        for f in sorted(findings, key=lambda f: (order.get(f.severidad, 9), f.objetivo)):
            ctx.out.check(False, f"[{f.severidad}] {f.objetivo}  {f.titulo}")
            if f.datos.get("cifrados"):
                ctx.out.line("         " + ", ".join(f.datos["cifrados"][:4]) + (" ..." if len(f.datos["cifrados"]) > 4 else ""))
    else:
        ctx.out.ok("Sin hallazgos de TLS.")
    results.write(d / "hallazgos.txt", "\n".join(f"[{f.severidad}] {f.objetivo} {f.titulo}" for f in findings) + "\n")
    results.write(d / "hallazgos.json", recomendacion.to_json(findings))
    recomendacion.render(ctx, findings)


def revisar(ctx: Context, v: dict) -> bool:
    text = (v.get("objetivo") or "").strip()
    if text:
        groups, bad = _split_targets(text)
        if bad:
            ctx.out.error("Objetivos no válidos: " + ", ".join(bad))
            return False
        if not scope.gate(ctx, " ".join(groups), v, "tls"):
            return False
        label = text.replace("/", "_")[:40]
    else:
        scan = ultimo(ctx)
        if scan is None:
            return False
        groups, label = targets_from_scan(scan), "ultimo_escaneo"
        if not groups:
            ctx.out.info("El último escaneo no tiene servicios con TLS (o no se hizo con detección de versiones).")
            return True
    extra_ports = (v.get("puertos") or "").replace(" ", "")
    if extra_ports:
        if not re.match(r"^[0-9,]+$", extra_ports):
            ctx.out.error("Puertos no válidos (ej.: 443,8443,3389)")
            return False
        groups = {h: set(map(int, filter(None, extra_ports.split(",")))) for h in groups}
    d = results.new_dir("tls", label)
    ctx.out.info(f"Revisando TLS en {len(groups)} equipos (s = detener)...")
    findings, rows = run_checks(ctx, groups, v, d)
    show(ctx, findings, rows, d)
    audit.record("tls_resultado", label, "OK", f"servicios={len(rows)} hallazgos={len(findings)}")
    return True


def caducidad(ctx: Context, v: dict) -> bool:
    """Inventario rápido de certificados (solo ssl-cert): qué caduca y cuándo."""
    text = (v.get("objetivo") or "").strip()
    if text:
        groups, bad = _split_targets(text)
        if bad or not scope.gate(ctx, " ".join(groups), v, "tls"):
            if bad:
                ctx.out.error("Objetivos no válidos: " + ", ".join(bad))
            return False
    else:
        scan = ultimo(ctx)
        if scan is None:
            return False
        groups = targets_from_scan(scan)
    days = tooling.int_in(v.get("dias_aviso"), 30, 1, 365)
    d = results.new_dir("tls", "caducidad")
    rows = []
    by_ports: dict = defaultdict(list)
    for host, ports in groups.items():
        by_ports[tuple(sorted(ports or TLS_PORTS))].append(host)
    for i, (ports, hosts) in enumerate(by_ports.items(), 1):
        out = d / f"cert_{i}"
        stream(ctx, ["nmap", "-Pn", "-p", ",".join(map(str, ports)), "--open", "--script", "ssl-cert", "-oA", str(out),
                     *hosts], accion="tls_caducidad", objetivo=" ".join(hosts), show=False)
        for h in nmapxml.parse(out.with_suffix(".xml")).up():
            for p in h.open_ports():
                c = parse_cert(p.scripts.get("ssl-cert", ""))
                if c:
                    rows.append([f"{h.ip}:{p.port}", c.get("cn", "-")[:30], c.get("emisor", "-")[:30],
                                 c.get("hasta", "?")[:10], c.get("dias", 99999)])
    if not rows:
        ctx.out.info("No se encontró ningún certificado.")
        return True
    rows.sort(key=lambda r: r[4])
    ctx.out.table(["Servicio", "Certificado (CN)", "Emisor", "Caduca", "Días"],
                  [[*r[:4], ("¡CADUCADO! " if r[4] < 0 else "⚠ " if r[4] < days else "") + str(r[4])] for r in rows])
    results.write(d / "certificados.csv", "servicio;cn;emisor;caduca;dias\n" + "\n".join(";".join(map(str, r)) for r in rows) + "\n")
    ctx.out.info(f"Inventario en {d / 'certificados.csv'}")
    return True


def testssl_param_help() -> str:
    return "Para el detalle completo de un servicio concreto usa «Web y TLS › TLS en profundidad (testssl)»."


class Tls(Module):
    full = True
    id = "tls"
    name = "TLS y certificados"
    category = "Ciberseguridad"
    summary = "Versiones, cifrados débiles y certificados de cualquier servicio con TLS (web, RDP, LDAPS, correo...)"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    optional = [cmd("sslscan", debian="sslscan", arch="sslscan", label="sslscan")]
    help = """\
# TLS y certificados

> Solo contra sistemas propios o con autorización por escrito.

Revisa **cualquier servicio con TLS**, no solo webs: HTTPS, RDP (3389), LDAPS (636/3269), correo
(465/993/995 y STARTTLS en 25/587/110/143), bases de datos, paneles de iLO/iDRAC, Proxmox, Docker...

**Revisar TLS** detecta lo que más aparece en los informes de Nessus y OpenVAS:

| Hallazgo | Equivale a |
|---|---|
| SSL 2.0 / 3.0 activos | «SSL Version 2 and 3 Protocol Detection», POODLE |
| TLS 1.0 / 1.1 | «TLS Version 1.0 Protocol Detection», «TLS 1.1 Deprecated» |
| 3DES / bloque de 64 bits | SWEET32 |
| RC4 | «Bar Mitzvah» |
| Cifrados anónimos, NULL, EXPORT | «SSL Anonymous Cipher Suites Supported» |
| Certificado autofirmado / no de confianza / nombre equivocado | «SSL Self-Signed», «Cannot Be Trusted», «Wrong Hostname» |
| Caducado o a punto de caducar | «SSL Certificate Expiry» |
| Firma SHA-1/MD5, clave RSA < 2048 | «Weak Hashing Algorithm», «RSA keys less than 2048 bits» |
| DH débil, renegociación insegura, compresión | Logjam, CVE-2009-3555, CRIME |
| Heartbleed, POODLE, CCS | sus CVE |

Sin objetivo, revisa **todos los servicios con TLS del último escaneo de puertos**. Con objetivo:
`equipo`, `equipo:puerto`, URL, varios separados por espacio o un fichero.

**Caducidad de certificados**: inventario rápido de todos los certificados ordenados por fecha de
caducidad (exportable a CSV).

**Opciones avanzadas**: puertos concretos, días de aviso de caducidad, no comprobar la confianza
(redes con CA interna no instalada en este equipo), velocidad, usar o no sslscan y opciones de nmap.
Si **sslscan** está instalado (Catálogo › opcionales) se comprueban además la renegociación y la
compresión.
"""

    def actions(self):
        obj = Param("objetivo", "Objetivo (vacío = servicios con TLS del último escaneo)", required=False,
                    suggest=_subnets, help="equipo, equipo:puerto, URL, red, varios separados por espacio o fichero")
        ok = scope.ok_param()
        A = dict(required=False, advanced=True)
        dias = Param("dias_aviso", "Avisar si el certificado caduca en menos de (días)", "int", 30, **A)
        return [
            Action("revisar", "Revisar TLS", revisar, params=[
                obj, ok, Param("puertos", "Puertos a revisar (sustituye a los detectados)", **A,
                               help="Ej.: 443,3389,636"),
                dias, Param("sin_confianza", "No comprobar si el certificado es de confianza", "bool", False, **A,
                            help="Útil si la CA interna no está instalada en este equipo"),
                Param("sslscan", "Usar sslscan (renegociación y compresión) si está instalado", "bool", True, **A),
                Param("tiempo", "Velocidad", "choice", "T4", choices=[("T2", "T2 educado"), ("T3", "T3 normal"),
                                                                      ("T4", "T4 rápido")], **A),
                tooling.p_extra("nmap", "--script-args tls.servername=www.ejemplo.local")]),
            Action("caducidad", "Caducidad de certificados", caducidad, params=[obj, ok, dias],
                   help="Inventario de certificados ordenado por fecha de caducidad."),
        ]
