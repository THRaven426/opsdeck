"""Web y TLS: cabeceras de seguridad, certificado y versiones de TLS de una web o de todas las webs
encontradas en el último escaneo; y, si están instalados, whatweb, nikto, testssl y búsqueda de rutas."""

from __future__ import annotations

import datetime as dt
import http.client
import re
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..core import audit, paths, recomendacion, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, any_cmd, cmd
from ..core.ops import stream
from .escaneo import ultimo


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
                    out["dias"] = (end - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days
                except ValueError:
                    out["caduca"] = line[9:].strip()
            elif "DNS:" in line:
                out["nombres"] = line.strip()
    return out


UA = "Mozilla/5.0 (X11; Linux x86_64) opsdeck-auditoria"
DEFAULT_PAGES = {"Welcome to nginx!": "nginx", "Apache2 Ubuntu Default Page": "Apache (Ubuntu)",
                 "Apache2 Debian Default Page": "Apache (Debian)", "IIS Windows Server": "IIS",
                 "Test Page for the Apache HTTP Server": "Apache (RHEL)", "It works!": "Apache"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def request(url: str, method: str = "GET", follow: bool = True, limit: int = 200_000, timeout: int = 8,
            extra_headers: Optional[dict] = None) -> dict:
    """Petición HTTP(S) sin verificar el certificado. Devuelve estado, cabeceras (las repetidas, como
    Set-Cookie, en lista), URL final y el principio del cuerpo."""
    hdrs = {"User-Agent": UA, **(extra_headers or {})}
    req = urllib.request.Request(url, method=method, headers=hdrs)
    handlers = [urllib.request.HTTPSHandler(context=_insecure_ctx())]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        r = opener.open(req, timeout=timeout)
        status, hlist, final = r.status, r.getheaders(), r.geturl()
        body = r.read(limit) if method not in ("HEAD", "OPTIONS") else b""
    except urllib.error.HTTPError as e:
        status, hlist, final = e.code, list(e.headers.items()), url
        try:
            body = e.read(limit)
        except Exception:
            body = b""
    except (urllib.error.URLError, OSError, ValueError, ssl.SSLError, http.client.HTTPException) as e:
        return {"estado": 0, "error": str(getattr(e, "reason", e)), "cabeceras": {}, "cookies": [], "cuerpo": b"", "url": url}
    single: dict = {}
    cookies = []
    for k, v in hlist:
        if k.lower() == "set-cookie":
            cookies.append(v)
        single[k.lower()] = v
    return {"estado": status, "cabeceras": single, "cookies": cookies, "url": final, "cuerpo": body}


def headers(url: str) -> dict:
    return request(url)


def _cookie_issues(cookies: list[str], https: bool) -> list[tuple[str, str]]:
    out = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in c.split(";")[1:]]
        miss = []
        if https and "secure" not in attrs:
            miss.append("Secure")
        if "httponly" not in attrs:
            miss.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            miss.append("SameSite")
        if miss:
            out.append((name, ", ".join(miss)))
    return out


def check_url(url: str, deep: bool = True) -> dict:
    u = urlparse(url)
    host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    res = {"url": url, "hallazgos": []}
    h = headers(url)
    res["http"] = h
    if h.get("error"):
        res["hallazgos"].append(("?", f"No responde: {h['error']}"))
        return res
    final_host = urlparse(h.get("url", url)).hostname or host
    if final_host != host and not scope.classify(final_host).ok:
        res["fuera_alcance"] = final_host
        res["hallazgos"].append(("?", f"Redirige a {final_host}, fuera del alcance: ese destino no se revisa"))
        h["url"] = url
    hd = h["cabeceras"]
    body = h.get("cuerpo", b"")[:200_000].decode("utf-8", "replace")
    final_https = h.get("url", url).startswith("https://")
    if hd.get("server") and any(ch.isdigit() for ch in hd["server"]):
        res["hallazgos"].append(("BAJO", f"Revela la versión del servidor: {hd['server']}"))
    if hd.get("x-powered-by"):
        res["hallazgos"].append(("BAJO", f"Revela la tecnología: X-Powered-By {hd['x-powered-by']}"))
    missing = [k for k in SEC_HEADERS if k not in hd and not (k == "strict-transport-security" and not final_https)]
    if missing:
        res["hallazgos"].append(("BAJO", "Faltan cabeceras de seguridad: " + ", ".join(missing)))
    sts = hd.get("strict-transport-security", "")
    if final_https and sts:
        m = re.search(r"max-age=(\d+)", sts)
        if not m or int(m.group(1)) < 15552000:
            res["hallazgos"].append(("BAJO", f"HSTS con max-age corto o mal formado: {sts[:60]}"))
    for name, miss in _cookie_issues(h.get("cookies", []), final_https):
        res["hallazgos"].append(("BAJO", f"Cookie {name} sin atributos {miss}"))
    if not final_https and re.search(r"<input[^>]+type=[\"']?password", body, re.I):
        res["hallazgos"].append(("MEDIO", "Formulario de contraseña servido por HTTP sin cifrar"))
    if u.scheme == "http" and not final_https:
        res["hallazgos"].append(("BAJO", "Se sirve por HTTP sin redirigir a HTTPS"))
    if re.search(r"<title>\s*Index of /", body, re.I):
        res["hallazgos"].append(("BAJO", "Listado de directorio activado"))
    for sig, prod in DEFAULT_PAGES.items():
        if sig in body:
            res["hallazgos"].append(("BAJO", f"Página por defecto de {prod}: servidor sin configurar o olvidado"))
            break
    if deep:
        opt = request(url, "OPTIONS", follow=False)
        allow = (opt["cabeceras"].get("allow", "") + "," + opt["cabeceras"].get("public", "")).upper()
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY")
                 if re.search(rf"\b{m}\b", allow)]
        if risky:
            res["hallazgos"].append(("MEDIO" if {"PUT", "DELETE"} & set(risky) else "BAJO",
                                     "Métodos HTTP peligrosos permitidos: " + ", ".join(risky)))
        tr = request(url, "TRACE", follow=False, limit=4000)
        if tr.get("estado") == 200 and b"TRACE /" in tr.get("cuerpo", b""):
            res["hallazgos"].append(("MEDIO", "TRACE habilitado (Cross-Site Tracing)"))
    if u.scheme == "https" or final_https:
        fu = urlparse(h["url"]) if final_https else u
        t = tls_info(fu.hostname or host, fu.port or (443 if fu.scheme == "https" else port))
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
            res["hallazgos"].append(("MEDIO", f"Certificado {t['confianza']}"))
    return res


# ---------------------------------------------------------------- ficheros sensibles

# (ruta, firma que confirma el contenido o None, severidad, qué es)
SENSITIVE = [
    (".git/HEAD", r"^ref: refs/", "ALTO", "Repositorio git expuesto (se puede descargar el código)"),
    (".git/config", r"\[core\]", "ALTO", "Configuración de git expuesta"),
    (".svn/entries", r"^(\d+|dir)\s", "MEDIO", "Repositorio Subversion expuesto"),
    (".env", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "ALTO", "Fichero .env con variables (suele tener contraseñas)"),
    (".htpasswd", r"(?m)^[^:\s]+:\$?[A-Za-z0-9./$]{10,}", "ALTO", "Hashes de contraseñas (.htpasswd)"),
    ("web.config", r"<configuration", "ALTO", "web.config expuesto"),
    ("WEB-INF/web.xml", r"<web-app", "ALTO", "Descriptor de aplicación Java expuesto"),
    ("server-status", r"Apache Server Status", "MEDIO", "Estado interno de Apache (server-status)"),
    ("server-info", r"Apache Server Information", "MEDIO", "Configuración de Apache (server-info)"),
    ("phpinfo.php", r"phpinfo\(\)|<title>PHP \d", "MEDIO", "phpinfo() expuesto"),
    ("info.php", r"phpinfo\(\)|<title>PHP \d", "MEDIO", "phpinfo() expuesto"),
    ("elmah.axd", r"Error Log for", "MEDIO", "Registro de errores ELMAH expuesto"),
    ("dump.sql", r"(CREATE TABLE|INSERT INTO)", "ALTO", "Volcado de base de datos"),
    ("backup.sql", r"(CREATE TABLE|INSERT INTO)", "ALTO", "Volcado de base de datos"),
    ("backup.zip", "PK\x03\x04", "ALTO", "Copia de seguridad descargable"),
    ("backup.tar.gz", "\x1f\x8b", "ALTO", "Copia de seguridad descargable"),
    (".DS_Store", "Bud1", "BAJO", "Fichero .DS_Store (revela nombres de ficheros)"),
    ("crossdomain.xml", r'allow-access-from domain="\*"', "BAJO", "crossdomain.xml permite cualquier dominio"),
    ("swagger.json", r'"(swagger|openapi)"', "BAJO", "Documentación de API expuesta"),
    ("api-docs", r'"(swagger|openapi)"', "BAJO", "Documentación de API expuesta"),
    ("v2/api-docs", r'"(swagger|openapi)"', "BAJO", "Documentación de API expuesta"),
    ("actuator/env", r'"(propertySources|activeProfiles)"', "ALTO", "Spring Boot Actuator expone variables"),
    ("actuator/heapdump", "JAVA PROFILE", "ALTO", "Spring Boot Actuator permite descargar la memoria"),
    ("~root/", None, "MEDIO", "Carpeta personal accesible por web (UserDir)"),
    ("~admin/", None, "MEDIO", "Carpeta personal accesible por web (UserDir)"),
    ("~nobody/", None, "MEDIO", "Carpeta personal accesible por web (UserDir)"),
    ("~bin/", None, "MEDIO", "Carpeta personal accesible por web (UserDir)"),
]


BINARY_SIGS = ("PK\x03\x04", "\x1f\x8b", "Bud1", "JAVA PROFILE")


def sensitive_files(base: str, extra_paths: list[str] | None = None, hdrs: Optional[dict] = None) -> list[tuple]:
    """Comprueba rutas sensibles con GET. Solo cuenta como hallazgo si el contenido lo confirma (o, sin
    firma, si la respuesta difiere de la de una ruta inexistente). Devuelve (ruta, estado, severidad, qué)."""
    import secrets
    base = base.rstrip("/")
    ref = request(f"{base}/{secrets.token_hex(8)}.html", follow=False, limit=20_000, extra_headers=hdrs)
    ref_len, ref_status = len(ref.get("cuerpo", b"")), ref.get("estado", 0)
    found = []
    items = list(SENSITIVE) + [(p.lstrip("/"), None, "BAJO", "Ruta indicada") for p in (extra_paths or [])]
    for path, sig, sev, what in items:
        r = request(f"{base}/{path}", follow=False, limit=200_000, extra_headers=hdrs)
        st = r.get("estado", 0)
        if st != 200:
            continue
        body = r.get("cuerpo", b"").decode("latin-1")
        if sig in BINARY_SIGS:
            if sig in body[:64]:
                found.append((path, st, sev, what))
        elif sig:
            if re.search(sig, body):
                found.append((path, st, sev, what))
        elif ref_status != 200 or abs(len(body) - ref_len) > 64:
            found.append((path, st, sev, what))
    rob = request(f"{base}/robots.txt", follow=False, limit=50_000, extra_headers=hdrs)
    if rob.get("estado") == 200:
        dis = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", rob.get("cuerpo", b"").decode("utf-8", "replace"))
        if dis:
            found.append(("robots.txt", 200, "INFO", "Rutas que se piden no indexar: " + " ".join(dis[:15])))
    return found


def _hdr_dict(ctx, v) -> Optional[dict]:
    hdrs, err = tooling.headers(v.get("cabeceras", ""))
    if err:
        ctx.out.error(err)
        return None
    return {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip() for h in hdrs}


def revisar(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    r = check_url(url, deep=v.get("metodos", True))
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
    if h.get("cookies"):
        ctx.out.title("Cookies")
        for c in h["cookies"][:10]:
            ctx.out.line("  " + c[:110])
    if "tls" in r:
        t = r["tls"]
        ctx.out.title("Certificado y TLS")
        ctx.out.table(["Dato", "Valor"], [["Versiones aceptadas", ", ".join(t["versiones"]) or "?"],
                                         ["Sujeto", t.get("sujeto", "?")], ["Emisor", t.get("emisor", "?")],
                                         ["Caduca", f"{t.get('caduca', '?')} ({t.get('dias', '?')} días)"],
                                         ["Nombres", t.get("nombres", "?")[:90]], ["Confianza", t.get("confianza", "?")]])
        ctx.out.info("Para cifrados débiles (RC4, 3DES/SWEET32, anónimos), renegociación o POODLE: módulo «TLS y certificados».")
    if v.get("ficheros"):
        base = f"{urlparse(h['url']).scheme}://{urlparse(h['url']).netloc}"
        for path, _st, sev, what in sensitive_files(base):
            r["hallazgos"].append((sev, f"{what}: /{path}"))
    if r["hallazgos"]:
        ctx.out.title("Hallazgos")
        for lvl, txt in r["hallazgos"]:
            ctx.out.check(False, f"[{lvl}] {txt}")
    else:
        ctx.out.ok("Sin hallazgos.")
    audit.record("web_revisar", url, "OK", f"{len(r['hallazgos'])} hallazgos")
    recomendacion.render(ctx, recomendacion.from_web(r))
    return True


def ficheros(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"]).rstrip("/")
    hd = _hdr_dict(ctx, v)
    if hd is None:
        return False
    extra = [x for x in re.split(r"[\s,]+", v.get("rutas_extra") or "") if x and re.match(r"^[A-Za-z0-9_./~%-]+$", x)]
    ctx.out.info(f"Comprobando {len(SENSITIVE) + len(extra) + 1} rutas sensibles en {url} (solo GET)...")
    found = sensitive_files(url, extra, hd)
    d = results.new_dir("web", f"ficheros_{urlparse(url).hostname or 'web'}")
    results.write(d / "ficheros.txt", "\n".join(f"[{s}] /{p} ({st}) {w}" for p, st, s, w in found) + "\n")
    audit.record("web_ficheros", url, "OK", f"{len(found)} hallazgos")
    if not found:
        ctx.out.ok("No se encontró ninguna ruta sensible expuesta.")
        return True
    ctx.out.table(["Severidad", "Ruta", "Qué es"], [[s, f"/{p}", w] for p, st, s, w in found])
    recomendacion.render(ctx, recomendacion.from_web({"url": url, "hallazgos": [(s, f"{w}: /{p}") for p, st, s, w in found
                                                                                 if s != "INFO"]}))
    return True


def webs_ultimo(ctx: Context, v: dict) -> bool:
    scan = ultimo(ctx)
    if scan is None:
        return False
    urls = []
    for h in scan.up():
        for p in h.open_ports():
            if p.is_web and p.proto == "tcp":
                urls.append(f"{'https' if p.is_tls else 'http'}://{h.ip}:{p.port}")
    if not urls:
        ctx.out.info("El último escaneo no tiene webs.")
        return True
    if not scope.gate(ctx, " ".join(urls), v, "web"):
        return False
    ctx.out.info(f"Revisando {len(urls)} webs...")
    rows, report, findings = [], [], []
    for u in urls:
        r = check_url(u, deep=v.get("metodos", True))
        if v.get("ficheros") and not r["http"].get("error"):
            for path, _st, sev, what in sensitive_files(u):
                r["hallazgos"].append((sev, f"{what}: /{path}"))
        findings += recomendacion.from_web(r)
        worst = min((x[0] for x in r["hallazgos"]), key=lambda l: ("ALTO", "MEDIO", "BAJO", "INFO", "?").index(l)
                    if l in ("ALTO", "MEDIO", "BAJO", "INFO", "?") else 9, default="")
        t = r.get("tls", {})
        rows.append([u, str(r["http"].get("estado", "-")), ", ".join(t.get("versiones", [])) or "-",
                     f"{t['dias']} d" if "dias" in t else "-", str(len(r["hallazgos"])), worst or "ok"])
        report.append(u + "\n" + "\n".join(f"  [{l}] {x}" for l, x in r["hallazgos"]))
    ctx.out.table(["URL", "HTTP", "TLS", "Cert. caduca", "Hallazgos", "Peor"], rows)
    d = results.new_dir("web", "webs_escaneo")
    results.write(d / "informe.txt", "\n\n".join(report) + "\n")
    ctx.out.info(f"Detalle de cada web en {d / 'informe.txt'}. Para una sola: 'Revisar una web'.")
    audit.record("web_revisar_escaneo", "ultimo_escaneo", "OK", f"{len(urls)} webs")
    recomendacion.render(ctx, findings)
    return True


def _tool(ctx, args: list[str], label: str, url: str, ok_rc=(0,)) -> tuple[int, str]:
    d = results.new_dir("web", f"{label}_{urlparse(url).hostname or 'web'}")
    tooling.show_cmd(ctx, args)
    results.write(d / "orden.txt", " ".join(tooling.redact(args)) + "\n")
    rc, out = stream(ctx, args, accion=f"web_{label}", objetivo=url, save_to=d / f"{label}.txt", keep=150, ok_rc=ok_rc)
    ctx.out.info(f"Salida completa en {d}")
    return rc, out


def _common(ctx, v, extra_forbidden=()) -> Optional[list[str]]:
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN + tuple(extra_forbidden))
    if err:
        ctx.out.error(err)
        return None
    return extra


def whatweb(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    extra = _common(ctx, v, ("--log-brief", "--log-verbose", "--log-json", "--log-xml", "-i", "--input-file"))
    px, err = tooling.proxy(v.get("proxy", ""))
    if extra is None or err:
        ctx.out.error(err) if err else None
        return False
    args = ["whatweb", "--color=never", "-a", v.get("agresividad") or "1", "--max-threads",
            str(tooling.int_in(v.get("hilos"), 25, 1, 100))]
    if v.get("agente"):
        args += ["-U", v["agente"]]
    if px:
        args += ["--proxy", px.split("://", 1)[1].rstrip("/")]
    hdrs, err = tooling.headers(v.get("cabeceras", ""))
    if err:
        ctx.out.error(err)
        return False
    for h in hdrs:
        args += ["-H", h]
    rc, _ = _tool(ctx, args + extra + [norm_url(v["url"])], "whatweb", norm_url(v["url"]))
    return rc == 0


NIKTO_TUNING = [("", "Todas las pruebas (por defecto)"), ("x6", "Todas salvo denegación de servicio"),
                ("123b", "Ficheros interesantes, configuración y software identificable"),
                ("2", "Configuración incorrecta / ficheros por defecto"), ("3", "Divulgación de información"),
                ("4", "Inyección (XSS/script/HTML)"), ("9", "Inyección SQL"), ("a", "Saltos de autenticación"),
                ("c", "Inclusión remota de ficheros")]


def nikto(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    extra = _common(ctx, v, ("-Format", "-F", "-Save", "-config", "-update"))
    if extra is None:
        return False
    secs = tooling.int_in(v.get("tiempo_max"), 15, 1, 600) * 60
    args = ["nikto", "-h", url, "-ask", "no", "-nointeractive", "-maxtime", f"{secs}s",
            "-timeout", str(tooling.int_in(v.get("espera"), 10, 1, 120))]
    tun = (v.get("tuning") or "").strip()
    if tun:
        if not re.match(r"^[0-9a-cx]+$", tun):
            ctx.out.error("Tuning no válido (usa letras/números de nikto: 0-9, a, b, c, x)")
            return False
        args += ["-Tuning", tun]
    if v.get("agente"):
        args += ["-useragent", v["agente"]]
    px, err = tooling.proxy(v.get("proxy", ""))
    if err:
        ctx.out.error(err)
        return False
    if px:
        args += ["-useproxy", px]
    if v.get("cgi"):
        args += ["-C", "all"]
    if v.get("sin_404"):
        args.append("-no404")
    rc, _ = _tool(ctx, args + extra, "nikto", url, ok_rc=(0, 1))
    return rc in (0, 1)


TESTSSL_MODES = [("", "Completo (todo)"), ("-p", "Solo protocolos"), ("-E", "Cifrados por protocolo"),
                 ("-U", "Solo vulnerabilidades (Heartbleed, POODLE, ROBOT, SWEET32...)"), ("-S", "Solo certificado"),
                 ("-h", "Solo cabeceras HTTP"), ("-s", "Grupos de cifrados estándar"), ("-f", "Secreto perfecto hacia delante")]
STARTTLS = [("", "No (TLS directo)"), ("smtp", "SMTP"), ("pop3", "POP3"), ("imap", "IMAP"), ("ftp", "FTP"),
            ("ldap", "LDAP"), ("xmpp", "XMPP"), ("postgres", "PostgreSQL"), ("mysql", "MySQL"), ("nntp", "NNTP")]


def testssl(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    exe = "testssl" if system.has_cmd("testssl") else "testssl.sh"
    raw = v["url"].strip()
    u = urlparse(norm_url(raw))
    try:
        port = u.port or (80 if raw.startswith("http://") else 443)
    except ValueError:
        ctx.out.error("Puerto no válido en la URL")
        return False
    if not u.hostname:
        ctx.out.error("URL sin equipo")
        return False
    target = f"[{u.hostname}]:{port}" if ":" in u.hostname else f"{u.hostname}:{port}"
    extra = _common(ctx, v, ("--logfile", "--jsonfile", "--csvfile", "--htmlfile", "--outfile", "--outFile",
                             "--file", "-iL", "--log", "--json", "--csv", "--html"))
    if extra is None:
        return False
    args = [exe, "--quiet", "--color", "0", "--warnings", "batch"]
    if v.get("modo"):
        args.append(v["modo"])
    if v.get("starttls"):
        args += ["-t", v["starttls"]]
    if v.get("severidad"):
        args += ["--severity", v["severidad"]]
    if v.get("rapido"):
        args.append("--sneaky")
    if v.get("ip"):
        args += ["--ip", "one"]
    rc, out = _tool(ctx, args + extra + [target], "testssl", norm_url(raw), ok_rc=tuple(range(0, 250)))
    if "doesn't seem to be a TLS/SSL enabled server" in out:
        ctx.out.error(f"{target} no habla TLS directamente. ¿Puerto correcto? ¿Necesita STARTTLS?")
        return False
    return "Done " in out or rc == 0


ENGINES = [("", "Automático (ffuf > feroxbuster > gobuster)"), ("ffuf", "ffuf"), ("feroxbuster", "feroxbuster (recursivo)"),
           ("gobuster", "gobuster")]


def wordlists() -> list[str]:
    own = paths.APP_DIR / "opsdeck" / "datos" / "rutas_comunes.txt"
    return [w for w in WORDLISTS if Path(w).exists()] + [str(own)]


def rutas(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"]).rstrip("/")
    wl = (v.get("diccionario") or "").strip() or next(iter(wordlists()), "")
    if not wl or not Path(wl).is_file():
        ctx.out.error(f"No encuentro el diccionario {wl or ''}. Instala 'seclists' o 'dirb', o indica la ruta de uno.")
        return False
    eng = v.get("motor") or next((e for e in ("ffuf", "feroxbuster", "gobuster") if system.has_cmd(e)), "")
    if not eng or not system.has_cmd(eng):
        ctx.out.error(f"No está instalado {eng or 'ningún buscador de rutas (ffuf, feroxbuster o gobuster)'}.")
        return False
    threads = str(tooling.int_in(v.get("hilos"), 20, 1, 200))
    codes = tooling.csv(v.get("codigos") or "200,204,301,302,307,401,403")
    exts = tooling.csv(v.get("extensiones") or "")
    rate = tooling.int_in(v.get("velocidad"), 0, 0, 5000)
    depth = tooling.int_in(v.get("profundidad"), 0, 0, 5)
    hdrs, err = tooling.headers(v.get("cabeceras", ""))
    px, err2 = tooling.proxy(v.get("proxy", ""))
    if err or err2:
        ctx.out.error(err or err2)
        return False
    if eng == "ffuf":
        args = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl, "-mc", codes, "-t", threads, "-s", "-noninteractive"]
        if exts:
            args += ["-e", ",".join(e if e.startswith(".") else f".{e}" for e in exts.split(","))]
        if rate:
            args += ["-rate", str(rate)]
        if depth:
            args += ["-recursion", "-recursion-depth", str(depth)]
        if v.get("redirecciones"):
            args.append("-r")
        if (v.get("filtro_tam") or "").strip():
            args += ["-fs", tooling.csv(v["filtro_tam"])]
        for h in hdrs:
            args += ["-H", h]
        if px:
            args += ["-x", px]
        forbidden = ("-o", "-of", "-od", "-or", "-input-cmd", "-request", "-config")
    elif eng == "feroxbuster":
        args = ["feroxbuster", "-u", url, "-w", wl, "-t", threads, "-q", "-k", "--no-state", "-d", str(depth or 1)]
        for c in codes.split(","):
            args += ["-s", c]
        if exts:
            args += ["-x", *[e.lstrip(".") for e in exts.split(",")]]
        if rate:
            args += ["--rate-limit", str(rate)]
        if v.get("redirecciones"):
            args.append("-r")
        if (v.get("filtro_tam") or "").strip():
            args += ["-S", tooling.csv(v["filtro_tam"])]
        for h in hdrs:
            args += ["-H", h]
        if px:
            args += ["-p", px]
        forbidden = ("-o", "--output", "--stdin", "--resume-from", "--debug-log")
    else:
        args = ["gobuster", "dir", "-u", url, "-w", wl, "-q", "-t", threads, "-k", "-s", codes, "-b", ""]
        if exts:
            args += ["-x", ",".join(e.lstrip(".") for e in exts.split(","))]
        if rate:
            args += ["--delay", f"{max(1, 1000 // rate)}ms", "-t", "1"]
        if v.get("redirecciones"):
            args.append("-r")
        if (v.get("filtro_tam") or "").strip():
            args += ["--exclude-length", tooling.csv(v["filtro_tam"])]
        for h in hdrs:
            args += ["-H", h]
        if px:
            args += ["--proxy", px]
        forbidden = ("-o", "--output")
    extra = _common(ctx, v, forbidden)
    if extra is None:
        return False
    if v.get("agente"):
        args += ({"ffuf": ["-H", f"User-Agent: {v['agente']}"], "feroxbuster": ["-a", v["agente"]],
                  "gobuster": ["-a", v["agente"]]})[eng]
    ctx.out.info(f"Diccionario: {wl}")
    rc, _ = _tool(ctx, args + extra, "rutas", url)
    return rc == 0


def wafw00f(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    args = ["wafw00f", "-a" if v.get("todos") else "-v", url]
    rc, _ = _tool(ctx, [a for a in args if a], "wafw00f", url)
    return rc == 0


def wpscan(ctx: Context, v: dict) -> bool:
    if not _scope_ok(ctx, v):
        return False
    url = norm_url(v["url"])
    enum = v.get("enumerar") or "vp,vt,tt,cb,dbe"
    if not re.match(r"^[a-z0-9,\-]+$", enum):
        ctx.out.error("Enumeración no válida")
        return False
    args = ["wpscan", "--url", url, "--no-banner", "--format", "cli-no-colour", "--disable-tls-checks",
            "--enumerate", enum, "--detection-mode", v.get("deteccion") or "mixed",
            "--max-threads", str(tooling.int_in(v.get("hilos"), 5, 1, 50))]
    if v.get("agente"):
        args += ["--user-agent", v["agente"]]
    px, err = tooling.proxy(v.get("proxy", ""))
    if err:
        ctx.out.error(err)
        return False
    if px:
        args += ["--proxy", px]
    extra = _common(ctx, v, ("--passwords", "-P", "--usernames", "-U", "--password-attack", "--output", "-o",
                             "--cookie-jar"))
    if extra is None:
        return False
    d = results.new_dir("web", f"wpscan_{urlparse(url).hostname or 'web'}")
    tooling.show_cmd(ctx, args + extra)
    cwd = None
    if v.get("token"):
        # El token no va en la orden (se vería en la lista de procesos): wpscan lo lee de
        # ./.wpscan/scan.yml en la carpeta de trabajo, que es privada y se borra al terminar.
        import shutil
        import tempfile
        cwd = tempfile.mkdtemp(prefix="opsdeck-wpscan-")
        cfg = Path(cwd) / ".wpscan"
        cfg.mkdir(mode=0o700)
        (cfg / "scan.yml").write_text(f"cli_options:\n  api_token: {v['token']}\n")
        (cfg / "scan.yml").chmod(0o600)
    try:
        rc, _ = stream(ctx, args + extra, accion="web_wpscan", objetivo=url, save_to=d / "wpscan.txt", keep=150,
                       ok_rc=(0, 5), cwd=cwd)
    finally:
        if cwd:
            shutil.rmtree(cwd, ignore_errors=True)
    ctx.out.info(f"Salida completa en {d}")
    return rc in (0, 5)


class Web(Module):
    full = True
    id = "web"
    name = "Web y TLS"
    category = "Ciberseguridad"
    summary = "Cabeceras, cookies, métodos, ficheros expuestos y TLS; whatweb, nikto, testssl, rutas, WAF, WordPress"
    requires = []
    optional = [cmd("whatweb", debian="whatweb", label="whatweb"), cmd("nikto", debian="nikto", label="nikto"),
                any_cmd(["testssl", "testssl.sh"], debian="testssl.sh", label="testssl"),
                cmd("ffuf", debian="ffuf", label="ffuf"), cmd("gobuster", debian="gobuster", label="gobuster"),
                cmd("wafw00f", debian="wafw00f", label="wafw00f"), cmd("wpscan", label="wpscan"),
                cmd("feroxbuster", label="feroxbuster")]
    help = """\
# Web y TLS

> Solo contra webs propias o con autorización por escrito.

Sin instalar nada:
- **Revisar una web**: cabeceras de seguridad (HSTS y su duración, CSP, anti-clickjacking...), si
  revela versiones, **cookies** sin Secure/HttpOnly/SameSite, **formularios de contraseña por HTTP**,
  web sin redirección a HTTPS, **listado de directorios**, **páginas por defecto**, **métodos HTTP
  peligrosos** (PUT, DELETE, TRACE, WebDAV), el **certificado** (emisor, nombres, días hasta caducar,
  confianza) y qué **versiones de TLS** acepta. Opcionalmente, también ficheros sensibles.
- **Ficheros y rutas sensibles**: `.git`, `.env`, `.htpasswd`, `web.config`, copias de seguridad,
  volcados SQL, `server-status`, `phpinfo`, Actuator, carpetas personales `~usuario` y `robots.txt`.
  Solo cuenta un hallazgo si el contenido lo confirma (evita falsos positivos de webs que responden
  200 a todo).
- **Revisar las webs del último escaneo**: lo mismo con todas las webs del *Escaneo de red*.

Si están instaladas (Catálogo › herramientas opcionales), aparecen además, cada una con sus
**opciones avanzadas**:
- **Tecnologías (whatweb)**: nivel de agresividad, agente, cabeceras, proxy.
- **Vulnerabilidades web (nikto)**: tipo de pruebas (*tuning*), tiempo máximo, CGI, agente, proxy.
- **TLS en profundidad (testssl)**: modo (protocolos, cifrados, vulnerabilidades, certificado,
  cabeceras), STARTTLS (SMTP, IMAP, LDAP, FTP, PostgreSQL...), severidad mínima.
- **Buscar rutas ocultas** con ffuf, feroxbuster o gobuster: extensiones, hilos, códigos, recursión,
  velocidad, filtro por tamaño, cabeceras (zonas autenticadas) y proxy. Si no hay diccionario
  instalado, usa uno mínimo incluido.
- **Detectar WAF (wafw00f)** y **WordPress (wpscan)**: versiones, plugins y temas vulnerables (sin
  ataques de contraseña).
"""

    def actions(self):
        url = Param("url", "URL o equipo:puerto", help="Ej.: https://intranet.ejemplo.local, 192.168.0.2:8443")
        ok = scope.ok_param()
        A = dict(required=False, advanced=True)
        net = [tooling.p_headers(), tooling.p_proxy(), tooling.p_useragent()]
        return [
            Action("revisar", "Revisar una web", revisar, params=[
                url, ok, Param("ficheros", "Buscar también ficheros sensibles", "bool", False, **A),
                Param("metodos", "Comprobar métodos HTTP (OPTIONS y TRACE)", "bool", True, **A)]),
            Action("ficheros", "Ficheros y rutas sensibles", ficheros, params=[
                url, ok, Param("rutas_extra", "Rutas adicionales a comprobar", **A, help="Separadas por espacio o coma"),
                tooling.p_headers()]),
            Action("escaneo", "Revisar las webs del último escaneo", webs_ultimo, params=[
                ok, Param("ficheros", "Buscar también ficheros sensibles", "bool", False, **A),
                Param("metodos", "Comprobar métodos HTTP (OPTIONS y TRACE)", "bool", True, **A)]),
            Action("whatweb", "Tecnologías (whatweb)", whatweb, requires=[cmd("whatweb")], params=[
                url, ok, Param("agresividad", "Agresividad", "choice", "1", choices=[
                    ("1", "1 sigiloso (una petición)"), ("3", "3 agresivo (más peticiones si reconoce algo)"),
                    ("4", "4 pesado (prueba todos los plugins)")], **A),
                tooling.p_threads(25), *net, tooling.p_extra("whatweb")]),
            Action("nikto", "Vulnerabilidades web (nikto)", nikto, requires=[cmd("nikto")], params=[
                url, ok, Param("tuning", "Tipo de pruebas (-Tuning)", "choice", "x6", choices=NIKTO_TUNING, **A),
                Param("tiempo_max", "Tiempo máximo (minutos)", "int", 15, **A), tooling.p_timeout(10),
                Param("cgi", "Probar todos los directorios CGI (-C all)", "bool", False, **A),
                Param("sin_404", "Desactivar la detección de páginas 404 falsas", "bool", False, **A),
                tooling.p_proxy(), tooling.p_useragent(), tooling.p_extra("nikto", "-Plugins headers;cookies")],
                confirm="nikto lanza miles de peticiones y queda registrado en la web. ¿Tienes autorización?"),
            Action("testssl", "TLS en profundidad (testssl)", testssl, requires=[any_cmd(["testssl", "testssl.sh"])], params=[
                url, ok, Param("modo", "Qué comprobar", "choice", "", choices=TESTSSL_MODES, **A),
                Param("starttls", "STARTTLS", "choice", "", choices=STARTTLS, **A),
                Param("severidad", "Mostrar desde severidad", "choice", "", choices=[
                    ("", "Todo"), ("LOW", "Baja"), ("MEDIUM", "Media"), ("HIGH", "Alta"), ("CRITICAL", "Crítica")], **A),
                Param("rapido", "Modo discreto (--sneaky)", "bool", False, **A),
                Param("ip", "Solo la primera IP del nombre (--ip one)", "bool", False, **A),
                tooling.p_extra("testssl", "--openssl-timeout 10")]),
            Action("rutas", "Buscar rutas ocultas", rutas, requires=[any_cmd(["ffuf", "feroxbuster", "gobuster"])], params=[
                url, Param("diccionario", "Diccionario (vacío = el primero disponible)", required=False,
                           suggest=wordlists), ok,
                Param("motor", "Herramienta", "choice", "", choices=ENGINES, **A),
                Param("extensiones", "Extensiones", **A, help="Ej.: php,bak,old,zip,txt"),
                Param("codigos", "Códigos HTTP a mostrar", "text", "200,204,301,302,307,401,403", **A),
                Param("filtro_tam", "Ocultar respuestas de este tamaño", **A, help="Para webs que responden 200 a todo"),
                Param("profundidad", "Recursión (niveles, 0 = sin recursión)", "int", 0, **A),
                Param("redirecciones", "Seguir redirecciones", "bool", False, **A),
                tooling.p_threads(20), tooling.p_rate(0, "Peticiones por segundo (0 = sin límite)"), *net,
                tooling.p_extra("la herramienta")],
                confirm="Se probarán miles de rutas contra la web. ¿Tienes autorización?"),
            Action("waf", "Detectar WAF (wafw00f)", wafw00f, requires=[cmd("wafw00f")], params=[
                url, ok, Param("todos", "No parar en el primero: probar todos los WAF conocidos", "bool", False, **A)]),
            Action("wpscan", "WordPress (wpscan)", wpscan, requires=[cmd("wpscan")], params=[
                url, ok, Param("enumerar", "Qué enumerar", "choice", "vp,vt,tt,cb,dbe", choices=[
                    ("vp,vt,tt,cb,dbe", "Plugins y temas vulnerables, timthumbs, copias de config y BBDD"),
                    ("ap,at,tt,cb,dbe", "Todos los plugins y temas (lento)"),
                    ("vp,vt,tt,cb,dbe,u1-10", "Lo anterior + usuarios 1-10")], **A),
                Param("deteccion", "Modo de detección", "choice", "mixed", choices=[
                    ("mixed", "Mixto"), ("passive", "Pasivo (menos ruido)"), ("aggressive", "Agresivo")], **A),
                Param("token", "Token de la API de WPScan (vulnerabilidades)", "password", required=False, advanced=True),
                tooling.p_threads(5), tooling.p_proxy(), tooling.p_useragent(), tooling.p_extra("wpscan")],
                confirm="wpscan enviará muchas peticiones a la web. ¿Tienes autorización?"),
        ]
