"""Instalar lo que necesita un módulo, con el flujo de apt: preparar el plan,
mostrarlo, pedir confirmación (lo hace quien llama) e instalar.

Con opcionales=True se añaden las herramientas opcionales del módulo (las que amplían lo que puede
hacer, como sslscan o ssh-audit) que falten y existan en los repositorios de esta distribución."""

from __future__ import annotations

from typing import Callable

from . import audit, packages, system
from .catalog import AVAILABLE, INSTALLABLE, Module


def wanted_packages(mod: Module, opcionales: bool = False) -> list[str]:
    st = mod.status()
    pkgs = list(st.packages) if st.state == INSTALLABLE else []
    if opcionales and st.state in (AVAILABLE, INSTALLABLE):
        pkgs += [p for r in mod.missing_optional() for p in r.pkgs()]
    return list(dict.fromkeys(pkgs))


def prepare(mod: Module, on_line: Callable[[str], None], opcionales: bool = False) -> packages.Plan:
    st = mod.status()
    pkgs = wanted_packages(mod, opcionales)
    if not pkgs:
        if st.state == AVAILABLE:
            return packages.Plan([], error="" if opcionales else "Nada que instalar")
        return packages.Plan([], error=st.reason or "Nada que instalar")
    pm = packages.manager()
    pm.refresh(on_line)
    return pm.plan(pm.missing(pkgs))


def install(mod: Module, plan: packages.Plan, on_line: Callable[[str], None]) -> bool:
    if not system.is_root():
        on_line("Hace falta root para instalar paquetes.")
        return False
    wanted = [p for p in plan.requested if p not in plan.unavailable]   # los que no existen harían fallar a apt
    if not wanted:
        on_line("Ninguno de los paquetes está en los repositorios de esta distribución.")
        return False
    rc = packages.manager().install(wanted, on_line)
    audit.record("instalar_dependencias", mod.id, "OK" if rc == 0 else f"ERROR_{rc}", " ".join(wanted))
    return rc == 0 and mod.status().state != INSTALLABLE
