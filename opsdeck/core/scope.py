"""Barandilla de alcance: confina los escaneos y las pruebas de red a las redes autorizadas.

No es un muro —quien tenga root puede saltarlo— sino un control deliberado y registrado:
evita que una prueba salga por error del alcance acordado y deja constancia de sobre qué
red se trabaja. Cualquier objetivo fuera del alcance exige una autorización explícita que
queda en el registro de auditoría.

El alcance autorizado se compone de:
  - las subredes a las que este equipo está conectado directamente (rutas «scope link»), y
  - las redes que se añadan en [red] redes_autorizadas de la configuración,
salvo que [red] solo_configuradas = true, en cuyo caso solo cuentan las configuradas.
El bucle local (127.0.0.0/8, ::1) está siempre dentro.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import audit, config, system

PARAM_OK = "alcance_ok"


# ---------------------------------------------------------------- redes autorizadas

def _parse_net(text: str):
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def configured_networks() -> list:
    raw = config.settings().get("red", "redes_autorizadas", fallback="")
    out = []
    for tok in raw.replace(",", " ").split():
        n = _parse_net(tok)
        if n is not None:
            out.append(n)
    return out


def local_networks() -> list:
    """Subredes conectadas directamente (lo que este equipo alcanza sin pasar por la puerta de enlace)."""
    out = []
    if not system.has_cmd("ip"):
        return out
    for fam in ("-4", "-6"):
        r = system.run(["ip", fam, "-o", "route", "show", "scope", "link"], c_locale=True)
        for line in r.out.splitlines():
            tok = line.split()
            if tok and "/" in tok[0]:
                n = _parse_net(tok[0])
                if n is not None and not n.is_loopback:
                    out.append(n)
    return out


def authorized_networks() -> list:
    nets: list = list(configured_networks())
    if not config.settings().getboolean("red", "solo_configuradas", fallback=False):
        nets += local_networks()
    nets.append(ipaddress.ip_network("127.0.0.0/8"))
    nets.append(ipaddress.ip_network("::1/128"))
    seen, uniq = set(), []
    for n in nets:
        if str(n) not in seen:
            seen.add(str(n))
            uniq.append(n)
    return uniq


# ---------------------------------------------------------------- clasificación de objetivos

def host_of(spec: str) -> str:
    """Quita esquema, ruta y puerto: «https://10.0.0.5:8443/x» → «10.0.0.5»; «[fe80::1]:443» → «fe80::1».
    Una red CIDR o un rango estilo nmap se devuelven tal cual."""
    spec = (spec or "").strip()
    if "://" in spec:
        spec = spec.split("://", 1)[1]
        spec = spec.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        spec = spec.rsplit("@", 1)[-1]              # usuario:clave@equipo
    if spec.startswith("["):                        # [IPv6]:puerto
        return spec[1:].split("]", 1)[0]
    if spec.count(":") == 1:                        # equipo:puerto (IPv4 o nombre)
        h, _, port = spec.partition(":")
        if port.isdigit():
            return h
    return spec


def _ip_bounds(spec: str):
    """(ip_min, ip_max) de una IP, red CIDR o rango estilo nmap. None si no es una forma numérica."""
    spec = spec.strip()
    if not spec:
        return None
    if "/" in spec:
        n = _parse_net(spec)
        return (n.network_address, n.broadcast_address) if n is not None else None
    if ":" in spec:                       # IPv6 sin prefijo
        try:
            a = ipaddress.ip_address(spec)
            return (a, a)
        except ValueError:
            return None
    parts = spec.split(".")
    if len(parts) != 4:
        return None
    lo, hi = [], []
    for p in parts:
        if "-" in p:
            a, _, b = p.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return None
            ai, bi = int(a), int(b)
        elif p.isdigit():
            ai = bi = int(p)
        else:
            return None
        if not (0 <= ai <= 255 and 0 <= bi <= 255 and ai <= bi):
            return None
        lo.append(ai)
        hi.append(bi)
    try:
        return (ipaddress.ip_address(".".join(map(str, lo))),
                ipaddress.ip_address(".".join(map(str, hi))))
    except ValueError:
        return None


def _resolve(host: str) -> list:
    try:
        return sorted({ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)})
    except (socket.gaierror, ValueError, OSError):
        return []


def _inside(ip, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def _specs_from_text(text: str) -> list[str]:
    toks = text.split()
    if len(toks) == 1:
        p = Path(toks[0])
        if p.is_file():
            try:
                return [l.strip() for l in p.read_text().splitlines()
                        if l.strip() and not l.strip().startswith("#")]
            except OSError:
                return toks
    return toks


@dataclass
class Result:
    dentro: list = field(default_factory=list)
    fuera: list = field(default_factory=list)
    sin_resolver: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.fuera and not self.sin_resolver


def classify(text: str, nets: Optional[list] = None) -> Result:
    """Clasifica cada objetivo de 'text' en dentro / fuera / sin_resolver respecto al alcance."""
    nets = authorized_networks() if nets is None else nets
    res = Result()
    for spec in _specs_from_text(text):
        spec = host_of(spec) or spec
        b = _ip_bounds(spec)
        if b is not None:
            lo, hi = b
            (res.dentro if _inside(lo, nets) and _inside(hi, nets) else res.fuera).append(spec)
        else:
            ips = _resolve(spec)
            if not ips:
                res.sin_resolver.append(spec)
            elif all(_inside(ip, nets) for ip in ips):
                res.dentro.append(spec)
            else:
                res.fuera.append(spec)
    return res


# ---------------------------------------------------------------- barandilla

def gate(ctx, text: str, v: dict, accion: str = "red") -> bool:
    """True si se puede continuar. Si hay objetivos fuera del alcance, exige que v[alcance_ok]
    esté marcado; si no, bloquea. Tanto el bloqueo como la autorización quedan en la auditoría."""
    if not (text or "").strip():
        return True
    res = classify(text)
    if res.ok:
        return True
    nets = authorized_networks()
    problemas = res.fuera + res.sin_resolver
    if not v.get(PARAM_OK):
        ctx.out.error("Objetivos FUERA del alcance autorizado: " + ", ".join(problemas))
        if res.sin_resolver:
            ctx.out.line("  No se resuelven (se tratan como fuera de alcance): " + ", ".join(res.sin_resolver))
        ctx.out.line("  Alcance autorizado ahora: " + (", ".join(str(n) for n in nets) or "ninguno"))
        ctx.out.info("Si tienes autorización por escrito sobre esa red, añádela en "
                     "«Escaneo de red › Alcance autorizado», o marca «Autorizo trabajar fuera del "
                     "alcance» y repite. La decisión queda registrada en la auditoría.")
        audit.record(f"alcance_bloqueado_{accion}", " ".join(problemas), "BLOQUEADO",
                     "fuera del alcance autorizado")
        return False
    audit.record(f"alcance_fuera_{accion}", " ".join(problemas), "AUTORIZADO_MANUAL",
                 "alcance: " + ";".join(str(n) for n in nets))
    ctx.out.warn("AUTORIZACIÓN FUERA DE ALCANCE: " + ", ".join(problemas)
                 + " — queda registrado en la auditoría.")
    return True


def ok_param():
    """Casilla que, marcada, permite salir del alcance autorizado (con autorización por escrito)."""
    from .catalog import Param
    return Param(PARAM_OK, "Autorizo trabajar fuera del alcance definido", "bool", False, required=False,
                 help="Solo con autorización por escrito sobre esa red. Queda registrado en la auditoría.")
