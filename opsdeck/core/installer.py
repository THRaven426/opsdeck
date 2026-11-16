"""Instalar lo que necesita un módulo, con el flujo de apt: preparar el plan,
mostrarlo, pedir confirmación (lo hace quien llama) e instalar."""

from __future__ import annotations

from typing import Callable

from . import audit, packages, system
from .catalog import INSTALLABLE, Module


def prepare(mod: Module, on_line: Callable[[str], None]) -> packages.Plan:
    st = mod.status()
    pm = packages.manager()
    if st.state != INSTALLABLE:
        return packages.Plan([], error=st.reason or "Nada que instalar")
    pm.refresh(on_line)
    return pm.plan(pm.missing(st.packages))


def install(mod: Module, plan: packages.Plan, on_line: Callable[[str], None]) -> bool:
    if not system.is_root():
        on_line("Hace falta root para instalar paquetes.")
        return False
    rc = packages.manager().install(plan.requested, on_line)
    audit.record("instalar_dependencias", mod.id, "OK" if rc == 0 else f"ERROR_{rc}", " ".join(plan.requested))
    return rc == 0 and mod.status().state != INSTALLABLE
