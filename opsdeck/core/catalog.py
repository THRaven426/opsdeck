"""Catálogo de módulos y detección.

Cada módulo declara qué necesita (comandos, ficheros, servicios) y qué paquetes lo
proporcionan en cada familia de distribuciones. En cada arranque se evalúa todo:
si mañana instalas xrdp, el módulo de escritorio remoto aparece solo.

Cómo añadir un módulo: ver CONTRIBUTING en README.md y cualquier fichero de modules/."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from . import edition, packages, system

# ---------------------------------------------------------------- requisitos

@dataclass
class Req:
    """Algo que debe existir en el equipo. kind: cmd | file | unit"""
    kind: str
    value: str
    packages: dict[str, list[str]] = field(default_factory=dict)  # familia -> paquetes
    label: str = ""

    def ok(self) -> bool:
        if self.kind == "cmd":
            return system.has_cmd(self.value)
        if self.kind == "file":
            return Path(self.value).exists()
        if self.kind == "unit":
            return system.unit_exists(self.value)
        return False

    def describe(self) -> str:
        return self.label or {"cmd": "comando", "file": "fichero", "unit": "servicio"}[self.kind] + f" {self.value}"

    def pkgs(self) -> list[str]:
        return self.packages.get(system.os_family(), [])


def cmd(name, debian=None, rhel=None, suse=None, arch=None, label=""):
    return Req("cmd", name, _pk(debian, rhel, suse, arch), label)


def file(path, debian=None, rhel=None, suse=None, arch=None, label=""):
    return Req("file", path, _pk(debian, rhel, suse, arch), label)


def _pk(debian, rhel, suse, arch):
    out = {}
    for fam, v in (("debian", debian), ("rhel", rhel), ("suse", suse), ("arch", arch)):
        if v:
            out[fam] = v if isinstance(v, list) else [v]
    return out


# ---------------------------------------------------------------- acciones

@dataclass
class Param:
    """Dato que pide una acción. kind: text | password | bool | choice | user | group | int"""
    name: str
    label: str
    kind: str = "text"
    default: Any = ""
    required: bool = True
    choices: list[tuple[str, str]] = field(default_factory=list)   # (valor, texto)
    help: str = ""
    when: Optional[Callable[[], bool]] = None    # solo se pide si devuelve True
    suggest: Optional[Callable[[], list[str]]] = None   # valores que se proponen al escribir


@dataclass
class Action:
    id: str
    label: str
    run: Callable[["Context", dict], bool]
    help: str = ""
    params: list[Param] = field(default_factory=list)
    changes: bool = False          # modifica el sistema: copia previa + registro
    confirm: Any = ""              # texto (admite {param}) o función(valores) -> texto; vacío = sin confirmación
    requires: list[Req] = field(default_factory=list)
    group: str = ""                # encabezado bajo el que se muestra en el menú
    full: bool = False             # solo en la edición completa

    def available(self) -> bool:
        if self.full and not edition.allowed_full()[0]:
            return False
        return all(r.ok() for r in self.requires)

    def confirm_text(self, values: dict) -> str:
        if callable(self.confirm):
            return self.confirm(values) or ""
        try:
            return self.confirm.format(**values) if self.confirm else ""
        except (KeyError, IndexError):
            return self.confirm

    def visible_params(self) -> list[Param]:
        return [p for p in self.params if p.when is None or p.when()]


# ---------------------------------------------------------------- salida

class Output(Protocol):
    def info(self, msg: str) -> None: ...
    def ok(self, msg: str) -> None: ...
    def warn(self, msg: str) -> None: ...
    def error(self, msg: str) -> None: ...
    def line(self, msg: str = "") -> None: ...
    def title(self, msg: str) -> None: ...
    def table(self, headers: list[str], rows: list[list[str]]) -> None: ...
    def secret(self, label: str, value: str) -> None: ...
    def check(self, good: bool, msg: str) -> None: ...


@dataclass
class Context:
    out: Output
    interactive: bool = True


# ---------------------------------------------------------------- módulos

AVAILABLE, INSTALLABLE, UNAVAILABLE = "disponible", "instalable", "no disponible"


@dataclass
class Status:
    state: str
    missing: list[Req] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)   # paquetes que faltan en esta distro
    reason: str = ""


class Module:
    """Para dependencias alternativas (p. ej. ufw O firewalld) sobrescribe detect()."""
    id: str = ""
    name: str = ""
    category: str = "Sistemas"        # Sistemas | Blue team | Ciberseguridad
    summary: str = ""
    help: str = ""                    # markdown que se muestra con ?
    requires: list[Req] = []
    families: tuple[str, ...] = ("debian", "rhel", "suse", "arch")
    full: bool = False                # True = solo en la edición completa (y para su grupo)

    def actions(self) -> list[Action]:
        return []

    def status(self) -> Status:
        if self.full:
            ok, why = edition.allowed_full()
            if not ok:
                return Status(UNAVAILABLE, reason=why)
        return self.detect()

    def detect(self) -> Status:
        fam = system.os_family()
        if fam not in self.families:
            return Status(UNAVAILABLE, reason=f"Aún no soportado en esta distribución ({fam})")
        missing = [r for r in self.requires if not r.ok()]
        if not missing:
            return Status(AVAILABLE)
        pkgs = [p for r in missing for p in r.pkgs()]
        unresolved = [r for r in missing if not r.pkgs()]
        pm = packages.manager()
        if pkgs and not unresolved and pm.name != "ninguno":
            return Status(INSTALLABLE, missing, list(dict.fromkeys(pkgs)),
                          "Falta: " + ", ".join(r.describe() for r in missing))
        return Status(UNAVAILABLE, missing, reason="Falta: " + ", ".join(r.describe() for r in missing))

    def action(self, action_id: str) -> Optional[Action]:
        return next((a for a in self.actions() if a.id == action_id), None)


def all_modules() -> list[Module]:
    from ..modules import MODULES
    return [cls() for cls in MODULES]


def module(module_id: str) -> Optional[Module]:
    return next((m for m in all_modules() if m.id == module_id), None)


CATEGORIES = ("Sistemas", "Blue team", "Ciberseguridad")
