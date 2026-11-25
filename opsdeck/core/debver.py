"""Comparación de versiones de paquetes Debian/Ubuntu (mismo orden que `dpkg --compare-versions`).

Formato: [época:]versión_original[-revisión]. Sirve para saber si la versión de un paquete ya incluye
la corrección de un CVE que la distribución publicó con un número «antiguo» (backport)."""

from __future__ import annotations

import re
from functools import cmp_to_key

_VALID = re.compile(r"^(\d+:)?[0-9][A-Za-z0-9.+~:-]*$")


def valid(v: str) -> bool:
    return bool(v) and len(v) <= 128 and bool(_VALID.match(v))


def split(v: str) -> tuple[int, str, str]:
    """(época, versión original, revisión)"""
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def upstream(v: str) -> str:
    """Versión original sin época ni revisión: «1:9.6p1-3ubuntu13.5» → «9.6p1»."""
    return split(v)[1]


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare(a: str, b: str) -> int:
    """<0 si a < b, 0 si son iguales, >0 si a > b."""
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return ea - eb
    c = _cmp_part(ua, ub)
    if c:
        return c
    return _cmp_part(ra, rb)


key = cmp_to_key(compare)
