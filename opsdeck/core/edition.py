"""Ediciones: 'ligera' (administración diaria) y 'completa' (además, análisis y respuesta a incidentes).

La edición se elige al instalar (install.sh --edicion ...) y se guarda en la configuración.
En la completa, los módulos avanzados solo los pueden usar los miembros de un grupo del sistema.
Aviso honesto: quien tiene root en el equipo puede saltarse este control; sirve para ordenar
quién usa qué, no como barrera frente a un administrador."""

from __future__ import annotations

from . import accounts, system
from .config import settings

LIGHT, FULL = "ligera", "completa"


def current() -> str:
    v = settings().get("general", "edicion", fallback=LIGHT).strip().lower()
    return FULL if v in (FULL, "full") else LIGHT


def is_full() -> bool:
    return current() == FULL


def group() -> str:
    return settings().get("general", "grupo_completa", fallback="opsdeck-completa").strip()


def allowed_full() -> tuple[bool, str]:
    """¿Puede el operador usar los módulos de la edición completa? (sí/no, motivo)"""
    if not is_full():
        return False, "Solo en la edición completa (sudo ./install.sh --edicion completa)"
    op = system.operator()
    if op == "root":
        return True, ""
    g = group()
    if not accounts.group(g):
        return False, f"Restringido: no existe el grupo '{g}' (reinstala con --edicion completa)"
    if not accounts.is_member(op, g):
        return False, f"Restringido: '{op}' no pertenece al grupo '{g}'"
    return True, ""
