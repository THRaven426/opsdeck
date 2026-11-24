"""Consultas sobre cuentas locales (compartidas por Usuarios, Escritorio remoto, etc.)."""

from __future__ import annotations

import grp
import os
import pwd
import re
import secrets
import string
import time
from pathlib import Path
from typing import Optional

from . import system
from .config import settings

NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def login_def(key: str, default: int) -> int:
    try:
        for line in Path("/etc/login.defs").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == key:
                return int(parts[1])
    except (OSError, ValueError):
        pass
    return default


UID_MIN = login_def("UID_MIN", 1000)
UID_MAX = login_def("UID_MAX", 60000)
GID_MIN = login_def("GID_MIN", 1000)


def valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name or ""))


def sudoers_groups() -> set[str]:
    """Grupos que aparecen como «%grupo» en sudoers. Un grupo así da sudo aunque aún no exista."""
    files = [Path("/etc/sudoers")]
    d = Path("/etc/sudoers.d")
    if d.is_dir():
        files += sorted(p for p in d.iterdir() if p.is_file() and "." not in p.name and not p.name.endswith("~"))
    found: set[str] = set()
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.lstrip().startswith("#") and not line.lstrip().startswith(("#include", "#includedir")):
                continue
            found.update(re.findall(r"%:?([A-Za-z0-9_][A-Za-z0-9_.-]*)", line))
    return found


def reserved_name(name: str) -> str:
    """Motivo por el que un usuario o grupo nuevo no puede llamarse así; cadena vacía si puede.
    useradd crea un grupo con el nombre del usuario: si ese nombre es un grupo privilegiado que aún
    no existe (admin en Ubuntu, docker antes de instalarlo...), la cuenta nueva sería administradora."""
    if name in priv_groups() or name in ("admin", "sudo", "wheel", "root"):
        return f"'{name}' es un grupo privilegiado: una cuenta o grupo con ese nombre tendría sus permisos"
    if name in sudoers_groups():
        return f"sudoers da permisos al grupo '%{name}': una cuenta o grupo con ese nombre los heredaría"
    return ""


def user(name: str) -> Optional[pwd.struct_passwd]:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def group(name: str) -> Optional[grp.struct_group]:
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def is_local(name: str) -> bool:
    try:
        return any(line.split(":", 1)[0] == name for line in Path("/etc/passwd").read_text().splitlines())
    except OSError:
        return False


def is_human(uid: int) -> bool:
    return UID_MIN <= uid <= UID_MAX


def local_users(include_system: bool = False) -> list[pwd.struct_passwd]:
    out = []
    for line in Path("/etc/passwd").read_text().splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[2].isdigit():      # líneas NIS «+::::::» o mal formadas
            continue
        uid = int(f[2])
        if include_system or is_human(uid) or uid == 0:
            u = user(f[0])
            if u:
                out.append(u)
    return out


def human_names() -> list[str]:
    return [u.pw_name for u in local_users() if is_human(u.pw_uid)]


def local_groups() -> list[grp.struct_group]:
    out = []
    for line in Path("/etc/group").read_text().splitlines():
        name = line.split(":", 1)[0]
        g = group(name)
        if g:
            out.append(g)
    return out


def groups_of(name: str) -> list[str]:
    u = user(name)
    if not u:
        return []
    gids = os.getgrouplist(name, u.pw_gid)
    names = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            names.append(str(gid))
    return names


def is_member(name: str, grp_name: str) -> bool:
    return grp_name in groups_of(name)


def primary_group(name: str) -> str:
    u = user(name)
    try:
        return grp.getgrgid(u.pw_gid).gr_name if u else ""
    except KeyError:
        return str(u.pw_gid) if u else ""


def shadow(name: str) -> Optional[list[str]]:
    """Campos de /etc/shadow (solo root): nombre, hash, último cambio, min, max, aviso, inactivo, caduca."""
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            f = line.split(":")
            if f and f[0] == name:
                return (f + [""] * 9)[:9]
    except OSError:
        pass
    return None


def today_days() -> int:
    return int(time.time() // 86400)


def day2date(v: str) -> str:
    if not v or v in ("99999", "-1"):
        return "-"
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(v) * 86400))
    except ValueError:
        return v


def state(name: str) -> str:
    """activa | bloqueada | caducada | SIN-CLAVE | sin-login-pass | debe-cambiar | pass-caducada | ?"""
    s = shadow(name)
    if not s:
        return "?"
    _, h, last, _, mx, _, _, exp, _ = s
    today = today_days()
    last, mx, exp = (x if x.isdigit() else "" for x in (last, mx, exp))
    if exp and int(exp) <= today:
        return "caducada"
    if h == "":
        return "SIN-CLAVE"
    if h.startswith("!"):
        return "bloqueada"
    if h == "*":
        return "sin-login-pass"
    if last == "0":
        return "debe-cambiar"
    if mx and last and int(mx) < 99999 and int(last) + int(mx) < today:
        return "pass-caducada"
    return "activa"


def has_real_password(name: str) -> bool:
    s = shadow(name)
    return bool(s and s[1] not in ("", "*", "!", "!!", "!*") and len(s[1].lstrip("!")) > 2)


def sudo_summary(name: str) -> str:
    """no | si | si (NOPASSWD) | ?"""
    if not system.has_cmd("sudo"):
        return "?"
    r = system.run(["sudo", "-n", "-l", "-U", name], c_locale=True)
    if "may run the following" not in r.out:
        return "no"
    return "si (NOPASSWD)" if "NOPASSWD" in r.out else "si"


def sudo_rules(name: str) -> list[str]:
    r = system.run(["sudo", "-n", "-l", "-U", name], c_locale=True)
    if "may run the following" not in r.out:
        return []
    return [l.strip() for l in r.out.split("may run the following", 1)[1].splitlines()[1:] if l.strip()]


def admin_group() -> str:
    for g in ("sudo", "wheel", "admin"):
        if group(g):
            return g
    return ""


def priv_groups() -> list[str]:
    return settings().get("usuarios", "grupos_privilegiados").split()


def last_login(name: str) -> str:
    """Último inicio de sesión registrado. Con wtmpdb (Kali, Debian 13) no incluye RDP."""
    for tool in ("lastlog", "lastlog2"):
        if system.has_cmd(tool):
            r = system.run([tool, "-u", name], c_locale=True)
            lines = r.out.splitlines()
            if len(lines) < 2 or "Never logged in" in lines[1]:
                return "nunca"
            return " ".join(lines[1].split()[1:])
    if system.has_cmd("last"):
        r = system.run(["last", "-w", "-n", "1", name], c_locale=True)
        for line in r.out.splitlines():
            f = line.split()
            if f and f[0] == name:
                return " ".join(f[1:])
        return "nunca (según wtmp)"
    return "desconocido"


def sessions(name: Optional[str] = None) -> list[dict]:
    """Sesiones abiertas. loginctl ve SSH, consola y RDP; who no ve RDP."""
    out = []
    if system.has_cmd("loginctl") and system.systemd_available():
        r = system.run(["loginctl", "list-sessions", "--no-legend"], c_locale=True)
        for line in r.out.splitlines():
            f = line.split()
            if len(f) < 3:
                continue
            klass = f[5] if len(f) > 5 else ""
            if klass in ("manager", "manager-early", "greeter"):
                continue
            if name is None or f[2] == name:
                out.append({"id": f[0], "usuario": f[2], "tty": f[6] if len(f) > 6 else "-", "clase": klass})
        return out
    r = system.run(["who"], c_locale=True)
    for line in r.out.splitlines():
        f = line.split()
        if f and (name is None or f[0] == name):
            out.append({"id": "-", "usuario": f[0], "tty": f[1], "clase": "user"})
    return out


def process_count(name: str) -> int:
    r = system.run(["pgrep", "-c", "-u", name])
    try:
        return int(r.out.strip() or 0)
    except ValueError:
        return 0


def gen_password(length: Optional[int] = None) -> str:
    length = max(8, length or settings().getint("usuarios", "longitud_password"))
    symbols = "@#%+=_.-"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p) and any(c in symbols for c in p)):
            return p


def password_problem(p: str) -> str:
    minimum = settings().getint("usuarios", "minimo_password")
    if len(p) < minimum:
        return f"La contraseña debe tener al menos {minimum} caracteres"
    if ":" in p or "\n" in p:
        return "La contraseña no puede contener ':' ni saltos de línea"
    return ""


def valid_shell(sh: str) -> bool:
    if sh in (nologin(),):
        return True
    try:
        return sh in Path("/etc/shells").read_text().split()
    except OSError:
        return False


def nologin() -> str:
    for s in ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/false", "/bin/false"):
        if Path(s).exists():
            return s
    return "/bin/false"


def guard(name: str, operator: str = "", allow_self: bool = True) -> str:
    """Devuelve un motivo si no se debe actuar sobre la cuenta; cadena vacía si se puede."""
    if not is_local(name):
        return f"'{name}' no es un usuario local de este equipo"
    u = user(name)
    if u and u.pw_uid == 0:
        return f"No se permite esta operación sobre una cuenta con UID 0 ({name})"
    if u and not is_human(u.pw_uid):
        return f"'{name}' es una cuenta de sistema (UID {u.pw_uid}); no se gestiona desde aquí"
    if not allow_self and name == (operator or system.operator()):
        return f"No puedes aplicar esto a tu propia cuenta ({name})"
    return ""
