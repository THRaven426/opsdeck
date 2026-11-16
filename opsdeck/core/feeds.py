"""Frescura de las fuentes de datos de las que depende la detección.

opsdeck no detecta con el conocimiento del modelo (congelado), sino con fuentes que se actualizan
a diario: las plantillas de nuclei, la base de exploit-db (searchsploit) y las listas de paquetes
del sistema (de donde salen los parches). Una vulnerabilidad reciente se detecta si esas fuentes
ya la recogen, así que conviene tenerlas al día. Aquí se consulta su antigüedad y se avisa."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import system

HOME = Path(os.environ.get("HOME", "/root"))
NUCLEI_DIRS = [HOME / ".local/nuclei-templates", HOME / "nuclei-templates",
               Path("/root/.local/nuclei-templates"), Path("/root/nuclei-templates")]
EXPLOITDB = [Path("/usr/share/exploitdb/files_exploits.csv"), Path("/opt/exploitdb/files_exploits.csv")]
APT_LISTS = Path("/var/lib/apt/lists")

UMBRAL_DIAS = 14     # a partir de aquí se considera desactualizada


@dataclass
class Feed:
    nombre: str
    presente: bool
    edad_dias: Optional[int] = None
    detalle: str = ""

    @property
    def vieja(self) -> bool:
        return self.presente and self.edad_dias is not None and self.edad_dias > UMBRAL_DIAS


def _edad_dias(path: Path) -> Optional[int]:
    try:
        return int((time.time() - path.stat().st_mtime) / 86400)
    except OSError:
        return None


def _nuclei() -> Feed:
    if not system.has_cmd("nuclei"):
        return Feed("Plantillas de nuclei", False, detalle="nuclei no está instalado")
    d = next((p for p in NUCLEI_DIRS if p.exists()), None)
    if d is None:
        return Feed("Plantillas de nuclei", True, None, "sin descargar (usa «Actualizar fuentes»)")
    return Feed("Plantillas de nuclei", True, _edad_dias(d), str(d))


def _exploitdb() -> Feed:
    if not system.has_cmd("searchsploit"):
        return Feed("Base de exploit-db", False, detalle="searchsploit no está instalado")
    f = next((p for p in EXPLOITDB if p.exists()), None)
    if f is None:
        return Feed("Base de exploit-db", True, None, "instalada, ubicación no habitual")
    return Feed("Base de exploit-db", True, _edad_dias(f), str(f.parent))


def _apt() -> Feed:
    if not APT_LISTS.exists():
        return Feed("Listas de paquetes (apt)", False, detalle="no es un sistema apt")
    return Feed("Listas de paquetes (apt)", True, _edad_dias(APT_LISTS), "última vez: apt-get update")


def status() -> list[Feed]:
    return [_nuclei(), _exploitdb(), _apt()]


def stale(feeds: Optional[list[Feed]] = None) -> list[Feed]:
    return [f for f in (feeds or status()) if f.vieja]


def warn_if_stale(ctx, feeds: Optional[list[Feed]] = None) -> None:
    viejas = stale(feeds)
    if viejas:
        ctx.out.warn("Fuentes de datos sin actualizar (más de "
                     f"{UMBRAL_DIAS} días): " + ", ".join(f"{f.nombre} ({f.edad_dias} d)" for f in viejas))
        ctx.out.line("     Un análisis con fuentes viejas puede no ver lo más reciente. "
                     "Actualízalas en «Fuentes de datos › Actualizar fuentes».")
