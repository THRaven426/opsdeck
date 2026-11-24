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

# Opciones que ninguna herramienta puede recibir como «extra»: salida y listas de objetivos
# (la salida la gestiona opsdeck; las listas de objetivos pasan por la barandilla de alcance).
COMMON_FORBIDDEN = ("-o", "--output", "-oA", "-oN", "-oX", "-oG", "-oJ", "-oS", "-iL", "-l", "--list",
                    "-iR", "--resume", "--datadir", "--script-updatedb", "--stylesheet")

HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}:\s?[^\r\n]{0,512}$")
PROXY_RE = re.compile(r"^(https?|socks5h?|socks4)://[A-Za-z0-9._:@%-]+(:\d{1,5})?/?$")
CSV_RE = re.compile(r"^[A-Za-z0-9_.,/:*-]*$")


def extra_args(text: str, forbidden: tuple[str, ...] = COMMON_FORBIDDEN) -> tuple[list[str], str]:
    """Convierte el texto de «opciones adicionales» en argumentos. Devuelve (argumentos, error)."""
    text = (text or "").strip()
    if not text:
        return [], ""
    try:
        args = shlex.split(text)
    except ValueError as e:
        return [], f"Opciones mal escritas: {e}"
    bad, outside = [], []
    for a in args:
        if not a.startswith("-"):
            if _looks_like_target(a) and not _in_scope(a):
                outside.append(a)
            continue
        name = a.split("=", 1)[0]
        # nmap y nuclei aceptan también la forma larga con dos guiones («--oA», «--iL», «--u»)
        names = {name, "-" + name[2:]} if name.startswith("--") else {name}
        for f in forbidden:
            # coincidencia exacta, o forma pegada («-oX», «-ofichero») solo para opciones de una letra
            if f in names or (len(f) == 2 and not f.startswith("--") and name.startswith(f) and not name.startswith("--")):
                bad.append(a)
                break
    if bad:
        return [], ("No se permiten estas opciones (la salida y las listas de objetivos las gestiona opsdeck): "
                    + " ".join(bad))
    if outside:
        return [], ("Las opciones incluyen direcciones fuera del alcance autorizado (se tratarían como objetivos "
                    "que no pasan por la barandilla): " + " ".join(outside))
    return args, ""


def _looks_like_target(token: str) -> bool:
    from .scope import _ip_bounds
    return "://" in token or _ip_bounds(token) is not None


def _in_scope(token: str) -> bool:
    from .scope import classify
    return classify(token).ok


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


def show_cmd(ctx, args: list[str], hide: Optional[set[int]] = None) -> None:
    """Muestra la orden que se va a lanzar (sin secretos: posiciones en 'hide' se ocultan)."""
    shown = [("***" if hide and i in hide else a) for i, a in enumerate(args)]
    ctx.out.info("$ " + " ".join(shlex.quote(a) for a in shown))
