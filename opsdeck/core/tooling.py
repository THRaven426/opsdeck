"""Piezas comunes para dar opciones avanzadas a las herramientas externas (nmap, nuclei, nikto...).

Las opciones avanzadas son opcionales: si no se tocan, cada acción se lanza con los valores
recomendados. Cuando el usuario quiere más control, puede ajustar velocidad, hilos, tiempos,
proxy, cabeceras o añadir opciones propias de la herramienta. Esas opciones libres se validan:
nunca se pasan por una shell y no se permite cambiar dónde escribe la herramienta (eso lo gestiona
opsdeck para guardar resultados) ni leer listas de objetivos que esquiven la barandilla de alcance."""

from __future__ import annotations

import re
import shlex
from typing import Optional

from .catalog import Param

# Opciones que ninguna herramienta puede recibir como «extra»: salida, listas de objetivos y todo lo
# que haga leer, cargar o ejecutar ficheros (la herramienta corre como root). La salida la gestiona
# opsdeck; las listas de objetivos pasan por la barandilla de alcance.
COMMON_FORBIDDEN = ("-o", "--output", "-oA", "-oN", "-oX", "-oG", "-oJ", "-oS", "-iL", "-l", "--list",
                    "-iR", "--resume", "--datadir", "--script-updatedb", "--stylesheet", "--script-args-file",
                    "--excludefile", "--servicedb", "--versiondb", "--openssl", "--plugins", "--log-file",
                    "--logfile", "--jsonfile", "--csvfile", "--htmlfile", "--outfile", "--config", "--env-vars")

# Opciones legítimas que son prefijo de una prohibida (getopt y argparse aceptan abreviaturas).
_ABBREV_OK = {"data", "script", "script-args", "exclude", "open", "version", "output-mode", "plugin"}
# Extensiones de ficheros de código o de datos que una herramienta podría cargar
_FILE_EXT = re.compile(r"\.(nse|lua|rb|py|pl|sh|so|yaml|yml|json|txt|lst|conf|cfg|xml|csv|log|db|ini|js)$", re.I)
_IPV4ISH = re.compile(r"^[\d*,\-]+(\.[\d*,\-]+){3}(/\d{1,2})?$")
_HOSTISH = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*\.?$")

HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}:\s?[^\r\n]{0,512}$")
PROXY_RE = re.compile(r"^(https?|socks5h?|socks4)://[A-Za-z0-9._:@%-]+(:\d{1,5})?/?$")
CSV_RE = re.compile(r"^[A-Za-z0-9_.,/:*-]*$")


def _forbidden_name(token: str, forbidden: tuple[str, ...]) -> bool:
    """¿Es una opción prohibida, en cualquiera de las formas que aceptan las herramientas?
    -x y --x (nmap y nuclei aceptan las dos), pegada a su valor (-iLlista, -oNfichero, -ofichero) y
    abreviada (--resum, --datad: getopt y argparse completan el nombre)."""
    name = token.split("=", 1)[0]
    canon = name.lstrip("-")
    double = name.startswith("--")
    for f in forbidden:
        fc = f.lstrip("-")
        if canon == fc:
            return True
        if len(fc) >= 2 and fc[-1].isupper() and canon.startswith(fc):
            return True
        if len(fc) == 1 and not double and canon.startswith(fc):
            return True
        if double and len(canon) >= 3 and len(fc) > len(canon) and fc.startswith(canon) and canon not in _ABBREV_OK:
            return True
    return False


def _bad_value(value: str) -> str:
    """Motivo si un valor apunta a un fichero (ruta, ~, .., extensión de código o datos); '' si no."""
    if not value:
        return ""
    if "://" in value:
        return "" if re.match(r"^(https?|socks[45]h?)://", value, re.I) else "esquema no permitido"
    if value.startswith("~") or ".." in value:
        return "rutas no permitidas"
    if "/" in value:
        from .scope import _ip_bounds
        return "" if _ip_bounds(value) is not None else "rutas no permitidas"
    if _FILE_EXT.search(value):
        return "ficheros no permitidos"
    return ""


def script_args_problem(text: str) -> str:
    """Motivo si algún valor de --script-args señala a un fichero (userdb=/etc/shadow lo leería
    como root). Se admiten agentes de usuario tipo «Mozilla/5.0»."""
    for part in re.split(r"[,{}]", text or ""):
        value = part.split("=", 1)[1].strip() if "=" in part else ""
        if re.match(r"^[A-Za-z][\w.-]*/[\w.()-]+$", value):
            continue
        why = _bad_value(value)
        if why:
            return f"{why}: {part.strip()}"
    return ""


def _looks_like_target(token: str) -> bool:
    """Un valor suelto que una herramienta podría tomar como objetivo adicional."""
    from .scope import _ip_bounds
    if "=" in token:
        return False
    if "://" in token or _ip_bounds(token) is not None or _IPV4ISH.match(token):
        return True
    if token.isdigit() and int(token) > 0xFFFFFF:      # nmap acepta una IPv4 escrita como entero
        return True
    return bool(_HOSTISH.match(token))


def _in_scope(token: str) -> bool:
    from .scope import classify, host_of
    if _IPV4ISH.match(token) and not classify(token).dentro:
        return False
    return classify(host_of(token)).ok


def extra_args(text: str, forbidden: tuple[str, ...] = COMMON_FORBIDDEN) -> tuple[list[str], str]:
    """Convierte el texto de «opciones adicionales» en argumentos. Devuelve (argumentos, error).
    Nunca se pasan por una shell. Se rechazan las opciones prohibidas, los valores que señalan a
    ficheros y las direcciones o nombres fuera del alcance (se tratarían como objetivos extra)."""
    text = (text or "").strip()
    if not text:
        return [], ""
    try:
        args = shlex.split(text)
    except ValueError as e:
        return [], f"Opciones mal escritas: {e}"
    bad, files, outside = [], [], []
    for i, a in enumerate(args):
        if i and args[i - 1] == "--script-args" and not a.startswith("-"):
            if script_args_problem(a):
                files.append(a)
            continue
        if a.startswith("-"):
            if _forbidden_name(a, forbidden):
                bad.append(a)
                continue
            value = a.split("=", 1)[1] if "=" in a else ""
        else:
            value = a
        if _bad_value(value) or (a.startswith("--script-args=") and script_args_problem(value)):
            files.append(a)
        elif not a.startswith("-") and _looks_like_target(a) and not _in_scope(a):
            outside.append(a)
    if bad:
        return [], ("No se permiten estas opciones (la salida, las listas de objetivos y la carga de ficheros "
                    "las gestiona opsdeck): " + " ".join(bad))
    if files:
        return [], ("No se permiten rutas ni ficheros en las opciones adicionales (la herramienta se ejecuta "
                    "como root): " + " ".join(files))
    if outside:
        return [], ("Las opciones incluyen equipos o direcciones fuera del alcance autorizado (se tratarían "
                    "como objetivos que no pasan por la barandilla): " + " ".join(outside))
    return args, ""


def int_in(v, default: int, lo: int, hi: int) -> int:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def csv(text: str) -> str:
    """Lista separada por comas sin espacios; '' si tiene caracteres raros."""
    t = (text or "").replace(" ", "")
    return t if CSV_RE.match(t) else ""


def headers(text: str) -> tuple[list[str], str]:
    """Cabeceras HTTP «Nombre: valor» separadas por ';'. Devuelve (cabeceras, error)."""
    out = []
    for h in (text or "").split(";"):
        h = h.strip()
        if not h:
            continue
        if not HEADER_RE.match(h):
            return [], f"Cabecera no válida: {h!r} (formato «Nombre: valor», varias separadas por ;)"
        out.append(h)
    return out, ""


def proxy(text: str) -> tuple[str, str]:
    t = (text or "").strip()
    if not t:
        return "", ""
    if not PROXY_RE.match(t):
        return "", "Proxy no válido. Ej.: http://127.0.0.1:8080 o socks5://127.0.0.1:1080"
    return t, ""


# ---------------------------------------------------------------- parámetros avanzados reutilizables

def p_extra(tool: str, example: str = "") -> Param:
    return Param("extra", f"Opciones adicionales de {tool}", required=False, advanced=True,
                 help=("Se añaden tal cual al final (sin shell). " + (f"Ej.: {example}. " if example else "")
                       + "No se admiten opciones de salida ni listas de objetivos."))


def p_threads(default: int, label: str = "Hilos / concurrencia") -> Param:
    return Param("hilos", label, "int", default, required=False, advanced=True,
                 help="Más hilos = más rápido y más ruido/carga en el objetivo.")


def p_rate(default: int, label: str = "Peticiones por segundo (máximo)") -> Param:
    return Param("velocidad", label, "int", default, required=False, advanced=True,
                 help="Bájalo para servicios frágiles o para no saturar enlaces lentos.")


def p_timeout(default: int, label: str = "Tiempo de espera por petición (s)") -> Param:
    return Param("espera", label, "int", default, required=False, advanced=True)


def p_proxy() -> Param:
    return Param("proxy", "Proxy", required=False, advanced=True,
                 help="Para revisar lo que se envía con Burp/ZAP: http://127.0.0.1:8080")


def p_headers() -> Param:
    return Param("cabeceras", "Cabeceras HTTP adicionales", required=False, advanced=True,
                 help="«Nombre: valor», varias separadas por ;  Ej.: Cookie: sesion=abc; Authorization: Bearer xyz")


def p_useragent(default: str = "") -> Param:
    return Param("agente", "User-Agent", default=default, required=False, advanced=True,
                 help="Vacío = el de la herramienta. Útil si un WAF bloquea agentes de escáneres.")


_SECRET_HEADER = re.compile(r"^\s*(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|api-key|"
                            r"x-access-token|token)\s*:", re.I)


def redact(args: list[str], hide: Optional[set[int]] = None) -> list[str]:
    """La orden sin secretos, para pantalla, auditoría y orden.txt: cabeceras de credenciales,
    usuario:clave de un proxy o URL y las posiciones indicadas en 'hide'."""
    out = []
    for i, a in enumerate(args):
        if hide and i in hide:
            a = "***"
        elif _SECRET_HEADER.match(a):
            a = a.split(":", 1)[0] + ": ***"
        else:
            a = re.sub(r"(://)[^/@\s]+@", r"\1***@", a)
            a = re.sub(r"((?:pass|password|passwd|secret|token|apikey|api_key)\s*=\s*)[^,}\s]+", r"\1***", a, flags=re.I)
        out.append(a)
    return out


def show_cmd(ctx, args: list[str], hide: Optional[set[int]] = None) -> None:
    """Muestra la orden que se va a lanzar (sin secretos: posiciones en 'hide' se ocultan)."""
    shown = redact(args, hide)
    ctx.out.info("$ " + " ".join(shlex.quote(a) for a in shown))
