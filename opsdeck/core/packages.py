"""Gestor de paquetes del sistema, con el mismo flujo que apt:
1) actualizar el índice, 2) calcular qué se instalará y cuánto ocupa,
3) mostrarlo y pedir confirmación, 4) instalar mostrando la salida.

Debian/Ubuntu/Kali (apt) está completo. dnf, zypper y pacman tienen soporte básico
(sin cálculo de tamaño) y se irán completando."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import system


@dataclass
class Plan:
    requested: list[str]
    to_install: list[str] = field(default_factory=list)   # incluye dependencias
    download: str = ""
    disk: str = ""
    unavailable: list[str] = field(default_factory=list)  # no existen en los repositorios
    error: str = ""

    @property
    def nothing_to_do(self) -> bool:
        return not self.to_install and not self.unavailable and not self.error

    def summary(self) -> str:
        if self.error:
            return f"No se pudo calcular la instalación:\n{self.error}"
        lines = []
        if self.unavailable:
            lines.append("No encontrados en los repositorios: " + " ".join(self.unavailable))
        if self.to_install:
            extra = [p for p in self.to_install if p not in self.requested]
            lines.append("Se instalarán los siguientes paquetes:")
            lines.append("  " + " ".join(p for p in self.to_install if p in self.requested))
            if extra:
                lines.append(f"Y además {len(extra)} dependencias:")
                lines.append("  " + " ".join(extra))
            if self.download or self.disk:
                lines.append(f"Descarga: {self.download or '?'}  ·  Espacio en disco: {self.disk or '?'}")
        if not lines:
            lines.append("Todo lo necesario ya está instalado.")
        return "\n".join(lines)


class PackageManager:
    name = "ninguno"
    family = "desconocida"

    def is_installed(self, pkg: str) -> bool:
        return False

    def missing(self, pkgs: list[str]) -> list[str]:
        return [p for p in dict.fromkeys(pkgs) if not self.is_installed(p)]

    def refresh(self, on_line: Callable[[str], None], max_age_h: int = 6) -> int:
        return 0

    def plan(self, pkgs: list[str]) -> Plan:
        return Plan(pkgs, error="Gestor de paquetes no soportado en este sistema")

    def install(self, pkgs: list[str], on_line: Callable[[str], None]) -> int:
        on_line("Gestor de paquetes no soportado en este sistema")
        return 1

    def upgradable(self) -> list[str]:
        return []

    def upgrade(self, on_line: Callable[[str], None]) -> int:
        return 1


def _human(n: int) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


class Apt(PackageManager):
    name, family = "apt", "debian"
    ENV = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}

    def is_installed(self, pkg: str) -> bool:
        r = system.run(["dpkg-query", "-W", "-f=${Status}", pkg], c_locale=True)
        return r.ok and r.out.strip().endswith("install ok installed")

    def index_age_h(self) -> float:
        lists = Path("/var/lib/apt/lists")
        try:
            newest = max((p.stat().st_mtime for p in lists.iterdir() if p.name.endswith("Packages")),
                         default=0)
        except OSError:
            newest = 0
        return (time.time() - newest) / 3600 if newest else 1e9

    def refresh(self, on_line, max_age_h: int = 6) -> int:
        if self.index_age_h() < max_age_h:
            on_line(f"Índice de paquetes actualizado hace menos de {max_age_h} h: no hace falta apt-get update.")
            return 0
        on_line("$ apt-get update")
        return system.stream(["apt-get", "update"], on_line, env=self.ENV)

    def plan(self, pkgs: list[str]) -> Plan:
        plan = Plan(list(dict.fromkeys(pkgs)))
        if not plan.requested:
            return plan
        for p in plan.requested:
            r = system.run(["apt-cache", "show", "--no-all-versions", p], c_locale=True)
            if not r.ok or not r.out.strip():
                plan.unavailable.append(p)
        wanted = [p for p in plan.requested if p not in plan.unavailable]
        if not wanted:
            return plan
        sim = system.run(["apt-get", "install", "-s", *wanted], c_locale=True, env=self.ENV)
        if not sim.ok:
            plan.error = sim.text[-1500:]
            return plan
        plan.to_install = re.findall(r"^Inst (\S+)", sim.out, re.M)
        # Tamaños SIN ejecutar nada que pueda instalar: --print-uris solo lista las descargas
        # (ojo: "apt-get install --assume-no" instala sin preguntar si no hay dependencias extra).
        uris = system.run(["apt-get", "install", "--print-uris", "-qq", *wanted], c_locale=True, env=self.ENV)
        dl = sum(int(f[2]) for f in (l.split() for l in uris.out.splitlines()) if len(f) >= 3 and f[2].isdigit())
        plan.download = _human(dl) if dl else "0 B (ya descargado)"
        disk = 0
        for pkg in plan.to_install:
            show = system.run(["apt-cache", "show", "--no-all-versions", pkg], c_locale=True)
            m = re.search(r"^Installed-Size: (\d+)", show.out, re.M)
            disk += int(m.group(1)) * 1024 if m else 0
        plan.disk = _human(disk) if disk else "?"
        return plan

    def install(self, pkgs, on_line) -> int:
        on_line("$ apt-get install -y " + " ".join(pkgs))
        return system.stream(["apt-get", "install", "-y", *pkgs], on_line, env=self.ENV)

    def upgradable(self) -> list[str]:
        r = system.run(["apt", "list", "--upgradable"], c_locale=True)
        return [l.split("/", 1)[0] for l in r.out.splitlines() if "/" in l and "upgradable" in l]

    def upgrade(self, on_line) -> int:
        on_line("$ apt-get upgrade -y")
        return system.stream(["apt-get", "upgrade", "-y"], on_line, env=self.ENV)


class _Simple(PackageManager):
    """dnf / zypper / pacman: instalación básica sin cálculo de tamaños (experimental)."""
    query: list[str] = []
    install_cmd: list[str] = []

    def is_installed(self, pkg):
        return system.run([*self.query, pkg]).ok

    def plan(self, pkgs):
        return Plan(list(dict.fromkeys(pkgs)), to_install=list(dict.fromkeys(pkgs)))

    def install(self, pkgs, on_line):
        on_line("$ " + " ".join([*self.install_cmd, *pkgs]))
        return system.stream([*self.install_cmd, *pkgs], on_line)


class Dnf(_Simple):
    name, family = "dnf", "rhel"
    query, install_cmd = ["rpm", "-q"], ["dnf", "install", "-y"]


class Zypper(_Simple):
    name, family = "zypper", "suse"
    query, install_cmd = ["rpm", "-q"], ["zypper", "--non-interactive", "install"]


class Pacman(_Simple):
    name, family = "pacman", "arch"
    query, install_cmd = ["pacman", "-Q"], ["pacman", "-S", "--noconfirm", "--needed"]


_PM: Optional[PackageManager] = None


def manager() -> PackageManager:
    global _PM
    if _PM is None:
        for cls, cmd in ((Apt, "apt-get"), (Dnf, "dnf"), (Zypper, "zypper"), (Pacman, "pacman")):
            if system.has_cmd(cmd):
                _PM = cls()
                break
        else:
            _PM = PackageManager()
    return _PM
