"""Acceso al sistema: ejecutar comandos de forma segura y detectar qué hay instalado.

Reglas: nunca shell=True; los argumentos van en lista; salida en locale C cuando hay
que interpretarla; los secretos se pasan por stdin, nunca como argumento."""

from __future__ import annotations

import os
import pwd
import shutil
import socket
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def text(self) -> str:
        return (self.out + ("\n" + self.err if self.err else "")).strip()


def run(cmd: list[str], *, input: Optional[str] = None, c_locale: bool = False,
        timeout: Optional[int] = 120, env: Optional[dict] = None) -> Result:
    e = dict(os.environ)
    if c_locale:
        e["LC_ALL"] = "C"
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, input=input, capture_output=True, text=True,
                           timeout=timeout, env=e)
        return Result(p.returncode, p.stdout, p.stderr)
    except FileNotFoundError:
        return Result(127, "", f"no existe el comando: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return Result(124, "", f"tiempo agotado: {' '.join(cmd)}")


_CURRENT: Optional[subprocess.Popen] = None
STOPPED = 143


def stream(cmd: list[str], on_line: Callable[[str], None], *, env: Optional[dict] = None,
           input: Optional[str] = None, cwd=None) -> int:
    """Ejecuta mostrando la salida línea a línea. Se puede detener con stop_current()."""
    global _CURRENT
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                             text=True, env=e, bufsize=1, errors="replace", start_new_session=True, cwd=cwd)
    except FileNotFoundError:
        on_line(f"no existe el comando: {cmd[0]}")
        return 127
    _CURRENT = p
    try:
        if input is not None and p.stdin:
            p.stdin.write(input)
            p.stdin.close()
        assert p.stdout
        for line in p.stdout:
            on_line(line.rstrip("\n"))
        return p.wait()
    finally:
        _CURRENT = None


def stop_current() -> bool:
    """Detiene el proceso largo en curso (escaneo, análisis...). Devuelve True si había uno."""
    p = _CURRENT
    if p is None or p.poll() is not None:
        return False
    import signal
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except OSError:
        p.terminate()
    return True


def has_cmd(name: str) -> bool:
    if shutil.which(name):
        return True
    # root no siempre tiene /usr/sbin en PATH cuando se usa su sin "-"
    return any(Path(d, name).exists() for d in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"))


def which(name: str) -> str:
    return shutil.which(name) or next(
        (str(Path(d, name)) for d in ("/usr/sbin", "/sbin") if Path(d, name).exists()), name)


@lru_cache(maxsize=1)
def os_release() -> dict:
    data = {}
    for f in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            for line in Path(f).read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    data[k] = v.strip().strip('"')
            break
        except OSError:
            continue
    return data


def os_family() -> str:
    """debian | rhel | suse | arch | desconocida"""
    r = os_release()
    ids = (r.get("ID", "") + " " + r.get("ID_LIKE", "")).lower()
    for fam, keys in (("debian", ("debian", "ubuntu", "kali")), ("rhel", ("rhel", "fedora", "centos")),
                      ("suse", ("suse",)), ("arch", ("arch",))):
        if any(k in ids.split() for k in keys):
            return fam
    return "desconocida"


def os_pretty() -> str:
    return os_release().get("PRETTY_NAME", "Linux")


def hostname() -> str:
    return socket.gethostname().split(".")[0]


def _login_user() -> Optional[str]:
    """Usuario con el que se inició la sesión (loginuid del kernel). No cambia con sudo ni su y el
    usuario no lo puede fijar, a diferencia de SUDO_USER (sudo deja pasar variables con SETENV)."""
    try:
        uid = int(Path("/proc/self/loginuid").read_text().strip())
    except (OSError, ValueError):
        return None
    if uid in (-1, 4294967295):
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def operator() -> str:
    """Persona que usa la herramienta (no root, si entró con sudo). Decide quién accede a la edición
    completa y figura en la auditoría."""
    u = _login_user() or os.environ.get("SUDO_USER")
    if u:
        return u
    try:
        return os.getlogin()
    except OSError:
        return pwd.getpwuid(os.geteuid()).pw_name


def is_root() -> bool:
    return os.geteuid() == 0


def systemd_available() -> bool:
    return Path("/run/systemd/system").is_dir() and has_cmd("systemctl")


def service_state(unit: str) -> str:
    """active | inactive | failed | no-instalado | desconocido"""
    if not systemd_available():
        return "desconocido"
    r = run(["systemctl", "is-active", unit], c_locale=True)
    state = r.out.strip()
    if state in ("active", "inactive", "failed", "activating", "deactivating"):
        if state == "inactive":
            exists = run(["systemctl", "list-unit-files", f"{unit}.service", "--no-legend"], c_locale=True)
            if not exists.out.strip():
                return "no-instalado"
        return state
    return "desconocido"


def unit_exists(unit: str) -> bool:
    if not systemd_available():
        return False
    r = run(["systemctl", "list-unit-files", f"{unit}.service", "--no-legend"], c_locale=True)
    return bool(r.out.strip())
