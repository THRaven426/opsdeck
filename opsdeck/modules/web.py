"""Web y TLS: cabeceras de seguridad, certificado y versiones de TLS de una web o de todas las webs
encontradas en el último escaneo; y, si están instalados, whatweb, nikto, testssl y búsqueda de rutas."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from ..core import audit, nmapxml, recomendacion, results, scope, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from .escaneo import escaneos


def _scope_ok(ctx: Context, v: dict) -> bool:
    return scope.gate(ctx, urlparse(norm_url(v["url"])).hostname or "", v, "web")

SEC_HEADERS = {
    "strict-transport-security": "HSTS (obliga a usar HTTPS)",
    "content-security-policy": "CSP (limita scripts externos / XSS)",
    "x-frame-options": "Anti-clickjacking",
    "x-content-type-options": "Evita interpretar ficheros con otro tipo",
    "referrer-policy": "Controla qué se envía como Referer",
}
WORDLISTS = ["/usr/share/wordlists/dirb/common.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt",
             "/usr/share/dirb/wordlists/common.txt"]


def norm_url(u: str) -> str:
    u = u.strip()
    return u if u.startswith(("http://", "https://")) else f"https://{u}"


def _insecure_ctx(minv=None, maxv=None) -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if minv:
        c.minimum_version = minv
    if maxv:
        c.maximum_version = maxv
    return c


def tls_info(host: str, port: int) -> dict:
    info: dict = {"versiones": [], "error": ""}
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                      ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)):
        try:
            with socket.create_connection((host, port), timeout=5) as s, \
                    _insecure_ctx(ver, ver).wrap_socket(s, server_hostname=host):
                info["versiones"].append(name)
        except (ssl.SSLError, OSError, ValueError):
            continue
    try:
        with socket.create_connection((host, port), timeout=5) as s, \
                _insecure_ctx().wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
        verified = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=5) as s, verified.wrap_socket(s, server_hostname=host):
                info["confianza"] = "válido y de confianza"
        except ssl.SSLCertVerificationError as e:
            info["confianza"] = f"NO de confianza ({e.verify_message})"
        except (ssl.SSLError, OSError):
            info["confianza"] = "?"
        info.update(_cert_fields(der))
    except (ssl.SSLError, OSError) as e:
        info["error"] = str(e)
    return info


def _cert_fields(der: bytes) -> dict:
    """Datos básicos del certificado sin dependencias externas (vía openssl si está, si no lo mínimo)."""
    out: dict = {}
    if system.has_cmd("openssl"):
        pem = ssl.DER_cert_to_PEM_cert(der)
        r = system.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-ext", "subjectAltName"],
                       input=pem, c_locale=True)
        for line in r.out.splitlines():
            if line.startswith("subject="):
                out["sujeto"] = line[8:].strip()
            elif line.startswith("issuer="):
                out["emisor"] = line[7:].strip()
            elif line.startswith("notAfter="):
                try:
                    end = dt.datetime.strptime(line[9:].strip(), "%b %d %H:%M:%S %Y %Z")
                    out["caduca"] = end.strftime("%Y-%m-%d")
                    out["dias"] = (end - dt.datetime.utcnow()).days
                except ValueError:
                    out["caduca"] = line[9:].strip()
            elif "DNS:" in line:
                out["nombres"] = line.strip()
    return out


def headers(url: str) -> dict:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "opsdeck-auditoria"})
    try:
        with urllib.request.urlopen(req, timeout=8, context=_insecure_ctx()) as r:
            return {"estado": r.status, "cabeceras": {k.lower(): v for k, v in r.getheaders()}, "url": r.geturl()}
    except urllib.error.HTTPError as e:
        return {"estado": e.code, "cabeceras": {k.lower(): v for k, v in e.headers.items()}, "url": url}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"estado": 0, "error": str(getattr(e, "reason", e)), "cabeceras": {}}


def check_url(url: str) -> dict:
    u = urlparse(url)
    host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    res = {"url": url, "hallazgos": []}
    h = headers(url)
    res["http"] = h
    if h.get("error"):
        res["hallazgos"].append(("?", f"No responde: {h['error']}"))
        return res
    hd = h["cabeceras"]
    if hd.get("server") and any(ch.isdigit() for ch in hd["server"]):
        res["hallazgos"].append(("BAJO", f"Revela la versión del servidor: {hd['server']}"))
    if hd.get("x-powered-by"):
        res["hallazgos"].append(("BAJO", f"Revela la tecnología: X-Powered-By {hd['x-powered-by']}"))
    missing = [k for k in SEC_HEADERS if k not in hd and not (k == "strict-transport-security" and u.scheme == "http")]
    if missing:
        res["hallazgos"].append(("BAJO", "Faltan cabeceras de seguridad: " + ", ".join(missing)))
    if u.scheme == "https":
        t = tls_info(host, port)
        res["tls"] = t
        old = [x for x in t["versiones"] if x in ("TLS 1.0", "TLS 1.1")]
        if old:
            res["hallazgos"].append(("MEDIO", f"Acepta versiones obsoletas: {', '.join(old)}"))
        if "dias" in t:
            if t["dias"] < 0:
                res["hallazgos"].append(("ALTO", f"Certificado CADUCADO el {t['caduca']}"))
            elif t["dias"] < 30:
                res["hallazgos"].append(("MEDIO", f"El certificado caduca en {t['dias']} días ({t['caduca']})"))
        if t.get("confianza", "").startswith("NO"):
            res["hallazgos"].append(("BAJO", f"Certificado {t['confianza']}"))
    return res


def revisar(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    r = check_url(url)
    h = r["http"]
    ctx.out.title(url)
    if h.get("error"):
        ctx.out.error(f"No responde: {h['error']}")
        if url.startswith("https://") and not v["url"].startswith("https"):
            ctx.out.info("Si la web es solo HTTP, escribe la URL completa con http://")
        return False
    ctx.out.line(f"  Respuesta HTTP {h['estado']}" + (f" · redirige a {h['url']}" if h["url"] != url else ""))
    ctx.out.title("Cabeceras de seguridad")
    for k, desc in SEC_HEADERS.items():
        ctx.out.check(k in h["cabeceras"], f"{desc}: {h['cabeceras'].get(k, 'falta')[:80]}")
    if "tls" in r:
        t = r["tls"]
        ctx.out.title("Certificado y TLS")
        ctx.out.table(["Dato", "Valor"], [["Versiones aceptadas", ", ".join(t["versiones"]) or "?"],
                                         ["Sujeto", t.get("sujeto", "?")], ["Emisor", t.get("emisor", "?")],
                                         ["Caduca", f"{t.get('caduca', '?')} ({t.get('dias', '?')} días)"],
                                         ["Nombres", t.get("nombres", "?")[:90]], ["Confianza", t.get("confianza", "?")]])
    if r["hallazgos"]:
        ctx.out.title("Hallazgos")
        for lvl, txt in r["hallazgos"]:
            ctx.out.check(False, f"[{lvl}] {txt}")
    else:
        ctx.out.ok("Sin hallazgos.")
    audit.record("web_revisar", url, "OK", f"{len(r['hallazgos'])} hallazgos")
    recomendacion.render(ctx, recomendacion.from_web(r))
    return True


def webs_ultimo(ctx: Context, v: dict) -> bool:
    scans = escaneos()
    if not scans:
        ctx.out.error("No hay escaneos guardados: haz antes un 'Escaneo de red' con perfil estándar o completo.")
        return False
    scan = nmapxml.parse(scans[0])
    urls = []
    for h in scan.up():
        for p in h.open_ports():
            if p.is_web and p.proto == "tcp":
                urls.append(f"{'https' if p.is_tls else 'http'}://{h.ip}:{p.port}")
    if not urls:
        ctx.out.info("El último escaneo no tiene webs.")
        return True
    ctx.out.info(f"Revisando {len(urls)} webs del escaneo {scans[0].parent.name}...")
    rows, report, findings = [], [], []
    for u in urls:
        r = check_url(u)
        findings += recomendacion.from_web(r)
        worst = min((x[0] for x in r["hallazgos"]), key=lambda l: ("ALTO", "MEDIO", "BAJO", "?").index(l), default="")
        t = r.get("tls", {})
        rows.append([u, str(r["http"].get("estado", "-")), ", ".join(t.get("versiones", [])) or "-",
                     f"{t['dias']} d" if "dias" in t else "-", worst or "ok"])
        report.append(u + "\n" + "\n".join(f"  [{l}] {x}" for l, x in r["hallazgos"]))
    ctx.out.table(["URL", "HTTP", "TLS", "Cert. caduca", "Peor hallazgo"], rows)
    d = results.new_dir("web", "webs_escaneo")
    results.write(d / "informe.txt", "\n\n".join(report) + "\n")
    ctx.out.info(f"Detalle de cada web en {d / 'informe.txt'}. Para una sola: 'Revisar una web'.")
    audit.record("web_revisar_escaneo", scans[0].parent.name, "OK", f"{len(urls)} webs")
    recomendacion.render(ctx, findings)
    return True


def _tool(ctx, args: list[str], label: str, url: str) -> bool:
    d = results.new_dir("web", f"{label}_{urlparse(url).hostname or 'web'}")
    rc, _ = stream(ctx, args, accion=f"web_{label}", objetivo=url, save_to=d / f"{label}.txt", keep=120)
    ctx.out.info(f"Salida completa en {d}")
    return rc == 0


def whatweb(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    return _tool(ctx, ["whatweb", "--color=never", "-a", "1", norm_url(v["url"])], "whatweb", norm_url(v["url"]))


def nikto(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    return _tool(ctx, ["nikto", "-h", url, "-ask", "no", "-nointeractive", "-maxtime", "15m"], "nikto", url)


def testssl(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    exe = "testssl" if system.has_cmd("testssl") else "testssl.sh"
    u = urlparse(norm_url(v["url"]))
    return _tool(ctx, [exe, "--quiet", "--color", "0", "--warnings", "batch", f"{u.hostname}:{u.port or 443}"],
                 "testssl", norm_url(v["url"]))


def rutas(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"]).rstrip("/")
    wl = v.get("diccionario") or next((w for w in WORDLISTS if Path(w).exists()), "")
    if not wl or not Path(wl).exists():
        ctx.out.error("No encuentro un diccionario. Instala 'dirb' o 'seclists', o indica la ruta de uno.")
        return False
    if system.has_cmd("ffuf"):
        args = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl, "-mc", "200,204,301,302,307,401,403", "-t", "20", "-s"]
    else:
        args = ["gobuster", "dir", "-u", url, "-w", wl, "-q", "-t", "20", "-k"]
    return _tool(ctx, args, "rutas", url)


class Web(Module):
    full = True
    id = "web"
    name = "Web y TLS"
    category = "Ciberseguridad"
    summary = "Cabeceras de seguridad, certificados y TLS; whatweb, nikto, testssl y rutas si están"
    requires = []
    help = """\
# Web y TLS

> Solo contra webs propias o con autorización por escrito.

Sin instalar nada:
- **Revisar una web**: cabeceras de seguridad (HSTS, CSP, anti-clickjacking...), si revela versiones,
  el **certificado** (emisor, nombres, **días hasta caducar**, si es de confianza) y qué **versiones de
  TLS** acepta (1.0 y 1.1 están obsoletas).
- **Revisar las webs del último escaneo**: hace lo mismo con todas las webs que encontró el
  *Escaneo de red* y muestra una tabla. Ideal para encontrar certificados a punto de caducar y
  paneles de administración olvidados.

Si están instalados (Kali los trae), aparecen además:
- **Tecnologías (whatweb)**, **Vulnerabilidades web (nikto)**, **TLS en profundidad (testssl)**
  y **Buscar rutas ocultas** (ffuf o gobuster con un diccionario).
"""

    def actions(self):
        url = Param("url", "URL o equipo:puerto", help="Ej.: https://intranet.empresa.local, 192.168.0.2:8443")
        ok = scope.ok_param()
        return [
            Action("revisar", "Revisar una web", revisar, params=[url, ok]),
            Action("escaneo", "Revisar las webs del último escaneo", webs_ultimo),
            Action("whatweb", "Tecnologías (whatweb)", whatweb, params=[url, ok], requires=[cmd("whatweb")]),
            Action("nikto", "Vulnerabilidades web (nikto)", nikto, params=[url, ok], requires=[cmd("nikto")],
                   confirm="nikto lanza miles de peticiones y queda registrado en la web. ¿Tienes autorización?"),
            Action("testssl", "TLS en profundidad (testssl)", testssl, params=[url, ok],
                   requires=[cmd("testssl" if system.has_cmd("testssl") else "testssl.sh")]),
            Action("rutas", "Buscar rutas ocultas", rutas, params=[
                url, Param("diccionario", "Diccionario (opcional)", required=False), ok],
                requires=[cmd("ffuf" if system.has_cmd("ffuf") else "gobuster")],
                confirm="Se probarán miles de rutas contra la web. ¿Tienes autorización?"),
        ]
