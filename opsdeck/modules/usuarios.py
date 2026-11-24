"""Usuarios: cuentas locales, contraseñas, grupos, sudo y sesiones."""

from __future__ import annotations

import os
import re
import stat
import tarfile
import tempfile
import time
from pathlib import Path

from ..core import accounts as acc
from ..core import audit, paths, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.config import settings
from ..core.ops import apply

STATE_HINT = {
    "activa": "puede entrar",
    "debe-cambiar": "tiene que cambiar la contraseña al entrar (por RDP no puede: ver Escritorio remoto)",
    "bloqueada": "bloqueada o sin contraseña asignada",
    "caducada": "cuenta caducada",
    "SIN-CLAVE": "¡entra SIN contraseña!",
    "sin-login-pass": "no admite contraseña (solo claves u otros métodos)",
    "pass-caducada": "la contraseña ha caducado",
}

def _err(ctx, msg) -> bool:
    ctx.out.error(msg)
    return False


def _guard(ctx, name, allow_self=True) -> bool:
    if not acc.user(name):
        return _err(ctx, f"No existe el usuario '{name}'")
    why = acc.guard(name, allow_self=allow_self)
    return _err(ctx, why) if why else True


# ------------------------------------------------------------------ consultas

def listar(ctx: Context, v: dict) -> bool:
    rows = []
    for u in acc.local_users(include_system=v.get("todos", False)):
        s = acc.shadow(u.pw_name)
        last = s[2] if s else ""
        rows.append([u.pw_name, str(u.pw_uid), acc.state(u.pw_name), os.path.basename(u.pw_shell),
                     "forzado" if last == "0" else acc.day2date(last),
                     ",".join(acc.groups_of(u.pw_name))[:60]])
    ctx.out.table(["Usuario", "UID", "Estado", "Shell", "Últ. cambio", "Grupos"], rows)
    ctx.out.info("Estados: " + " · ".join(f"{k} = {h.split('(')[0].strip()}" for k, h in STATE_HINT.items()
                                          if k in {r[2] for r in rows}))
    return True


def ficha(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    u = acc.user(name)
    if not u:
        return _err(ctx, f"No existe el usuario '{name}'")
    st = acc.state(name)
    home = Path(u.pw_dir)
    hp = f"{home.owner()}:{home.group()} {oct(home.stat().st_mode)[-3:]}" if home.exists() else "no existe"
    ses = acc.sessions(name)
    ctx.out.title(f"Usuario {name}")
    ctx.out.table(["Dato", "Valor"], [
        ["UID / GID", f"{u.pw_uid} / {u.pw_gid} ({acc.primary_group(name)})"],
        ["Nombre", u.pw_gecos or "-"],
        ["Home", f"{u.pw_dir} ({hp})"],
        ["Shell", u.pw_shell],
        ["Grupos", ", ".join(acc.groups_of(name))],
        ["Estado", f"{st}: {STATE_HINT.get(st, '')}"],
        ["Último login", acc.last_login(name)],
        ["Sesiones / procesos", f"{len(ses)} / {acc.process_count(name)}"],
        ["Sudo", acc.sudo_summary(name)],
    ])
    for g in acc.groups_of(name):
        if g in acc.priv_groups():
            ctx.out.warn(f"Pertenece al grupo privilegiado '{g}'")
    s = acc.shadow(name)
    if s:
        ctx.out.title("Contraseña y caducidad")
        ctx.out.table(["Dato", "Valor"], [
            ["Último cambio", "forzado (debe cambiarla)" if s[2] == "0" else acc.day2date(s[2])],
            ["Validez (días)", "no caduca" if s[4] in ("", "99999") else s[4]],
            ["Cuenta caduca", acc.day2date(s[7])],
        ])
    rules = acc.sudo_rules(name)
    if rules:
        ctx.out.title("Permisos sudo")
        for r in rules:
            ctx.out.line("  " + r)
    return True


def quien_sudo(ctx: Context, v: dict) -> bool:
    rows = []
    for name in ["root"] + acc.human_names():
        s = acc.sudo_summary(name)
        if s != "no":
            rows.append([name, s, acc.state(name)])
    ctx.out.title("Usuarios con sudo")
    ctx.out.table(["Usuario", "Sudo", "Estado"], rows)
    ctx.out.title("Reglas activas en sudoers")
    for f in [Path("/etc/sudoers"), *sorted(Path("/etc/sudoers.d").glob("*"))]:
        try:
            for line in f.read_text().splitlines():
                t = line.strip()
                if t and not t.startswith("#") and not t.startswith("Defaults"):
                    ctx.out.line(f"  {f}: {t}")
        except OSError:
            continue
    return True


def sesiones(ctx: Context, v: dict) -> bool:
    ses = acc.sessions()
    if not ses:
        ctx.out.info("No hay sesiones abiertas.")
        return True
    ctx.out.table(["Sesión", "Usuario", "TTY", "Tipo"], [[s["id"], s["usuario"], s["tty"], s["clase"]] for s in ses])
    return True


# ------------------------------------------------------------------ contraseñas

def _set_password(ctx, name, mode, manual, force) -> bool:
    if mode == "ninguna":
        ctx.out.warn(f"Sin contraseña: {name} no podrá entrar con contraseña hasta que se le asigne una.")
        return True
    if mode == "manual":
        problem = acc.password_problem(manual or "")
        if problem:
            return _err(ctx, problem)
        pw = manual
    else:
        pw = acc.gen_password()
    if not apply(ctx, "cambiar_password", name, ["chpasswd"], f"modo={mode} forzar_cambio={force}",
                 input=f"{name}:{pw}\n"):
        return False
    if force:
        apply(ctx, "forzar_cambio_password", name, ["chage", "-d", "0", name], quiet=True)
    if mode == "generar":
        ctx.out.secret(f"Contraseña de {name}", pw)
        ctx.out.warn("Se muestra solo esta vez y no se guarda. Entrégala por un canal seguro.")
    ctx.out.ok(f"Contraseña actualizada para {name}" + (" (deberá cambiarla al entrar)" if force else ""))
    return True


def restablecer(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name):
        return False
    return _set_password(ctx, name, v["modo"], v.get("password", ""), v["forzar"])


def forzar(ctx: Context, v: dict) -> bool:
    if not _guard(ctx, v["usuario"]):
        return False
    ok = apply(ctx, "forzar_cambio_password", v["usuario"], ["chage", "-d", "0", v["usuario"]])
    if ok:
        ctx.out.ok(f"{v['usuario']} deberá cambiar la contraseña en su próximo inicio de sesión.")
        ctx.out.warn("Por escritorio remoto (xrdp) no podrá: que entre antes por SSH o en la consola.")
    return ok


def quitar_cambio(ctx: Context, v: dict) -> bool:
    if not _guard(ctx, v["usuario"]):
        return False
    ok = apply(ctx, "quitar_cambio_obligatorio", v["usuario"],
               ["chage", "-d", time.strftime("%Y-%m-%d"), v["usuario"]])
    if ok:
        ctx.out.ok(f"{v['usuario']} ya puede entrar con su contraseña actual. Que la cambie con 'passwd'.")
    return ok


def caducidad(ctx: Context, v: dict) -> bool:
    name, fecha = v["usuario"], v["fecha"]
    if not _guard(ctx, name):
        return False
    if fecha in ("nunca", "-"):
        return apply(ctx, "caducidad_cuenta", name, ["chage", "-E", "-1", name], "nunca") and \
            (ctx.out.ok(f"{name} no caduca") or True)
    try:
        time.strptime(fecha, "%Y-%m-%d")
    except ValueError:
        return _err(ctx, "Fecha no válida: usa AAAA-MM-DD o 'nunca'")
    return apply(ctx, "caducidad_cuenta", name, ["chage", "-E", fecha, name], fecha) and \
        (ctx.out.ok(f"{name} caduca el {fecha}") or True)


# ------------------------------------------------------------------ alta / baja

def crear(ctx: Context, v: dict) -> bool:
    name, shell = v["usuario"], v["shell"] or settings().get("usuarios", "shell")
    if not acc.valid_name(name):
        return _err(ctx, "Nombre no válido: minúsculas, números, _ y -; empieza por letra o _; máx. 32")
    if acc.user(name):
        return _err(ctx, f"Ya existe '{name}'")
    if not acc.valid_shell(shell):
        return _err(ctx, f"La shell '{shell}' no está en /etc/shells")
    args = ["useradd", "-m", "-s", shell]
    if v.get("nombre"):
        if ":" in v["nombre"]:
            return _err(ctx, "El nombre completo no puede contener ':'")
        args += ["-c", v["nombre"]]
    groups = [g.strip() for g in (v.get("grupos") or "").split(",") if g.strip()]
    for g in groups:
        if not acc.group(g):
            return _err(ctx, f"No existe el grupo '{g}'")
        if g in acc.priv_groups():
            ctx.out.warn(f"'{g}' es un grupo privilegiado")
    if groups:
        args += ["-G", ",".join(groups)]
    if v.get("caduca"):
        try:
            time.strptime(v["caduca"], "%Y-%m-%d")
        except ValueError:
            return _err(ctx, "Fecha de caducidad no válida (AAAA-MM-DD)")
        args += ["-e", v["caduca"]]
    if not apply(ctx, "crear_usuario", name, args + [name],
                 f"shell={shell} grupos={','.join(groups) or '-'} caduca={v.get('caduca') or 'nunca'}"):
        return False
    home = acc.user(name).pw_dir
    if os.path.isdir(home):
        os.chmod(home, 0o750)
    ctx.out.ok(f"Usuario {name} creado (home {home}, permisos 750)")
    return _set_password(ctx, name, v["modo"], v.get("password", ""), v["forzar"])


def bloquear(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name, allow_self=False):
        return False
    prev = acc.day2date((acc.shadow(name) or [""] * 9)[7])
    if not apply(ctx, "bloquear_usuario", name, ["usermod", "-L", name], f"caducidad_previa={prev}"):
        return False
    apply(ctx, "caducar_cuenta", name, ["chage", "-E", "0", name], "bloqueo", quiet=True)
    ctx.out.ok(f"{name} bloqueado: no entra ni con contraseña ni con clave SSH.")
    if v.get("cerrar") and acc.process_count(name):
        _kill(ctx, name)
    elif acc.process_count(name):
        ctx.out.warn(f"{name} tiene procesos en marcha; sus sesiones abiertas siguen activas.")
    return True


def desbloquear(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name):
        return False
    s = acc.shadow(name) or [""] * 9
    if s[1].startswith("!"):
        if not acc.has_real_password(name):
            ctx.out.warn(f"{name} no tiene contraseña real: asígnale una con 'Restablecer contraseña'.")
        elif not apply(ctx, "desbloquear_usuario", name, ["usermod", "-U", name]):
            return False
    apply(ctx, "quitar_caducidad", name, ["chage", "-E", "-1", name], "desbloqueo", quiet=True)
    ctx.out.ok(f"{name} desbloqueado (sin fecha de caducidad; ponle una si era temporal).")
    return True


def _kill(ctx, name) -> None:
    if system.has_cmd("loginctl") and system.systemd_available():
        apply(ctx, "cerrar_sesiones", name, ["loginctl", "terminate-user", name], quiet=True)
        time.sleep(1)
    if acc.process_count(name):
        apply(ctx, "matar_procesos", name, ["pkill", "-KILL", "-u", name], quiet=True)
    ctx.out.ok(f"Sesiones y procesos de {name} cerrados.")


def cerrar_sesiones(ctx: Context, v: dict) -> bool:
    if not _guard(ctx, v["usuario"], allow_self=False):
        return False
    if not acc.process_count(v["usuario"]):
        ctx.out.info(f"{v['usuario']} no tiene procesos.")
        return True
    _kill(ctx, v["usuario"])
    return True


def eliminar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name, allow_self=False):
        return False
    if v.get("confirmacion") != name:
        return _err(ctx, "La confirmación no coincide con el nombre del usuario. No se ha borrado nada.")
    home = Path(acc.user(name).pw_dir)
    copy = ""
    if v.get("copia") and home.is_dir():
        paths.ensure_private_dir(paths.DATA_DIR, 0o750)
        paths.ensure_private_dir(paths.BACKUP_DIR)
        dest = paths.BACKUP_DIR / f"home_{name}_{time.strftime('%Y%m%d_%H%M%S')}.tar.gz"
        try:
            with tarfile.open(dest, "w:gz") as tar:
                tar.add(str(home), arcname=home.name)
            os.chmod(dest, 0o600)
            copy = str(dest)
            ctx.out.ok(f"Copia del home: {dest}")
        except OSError as e:
            return _err(ctx, f"Falló la copia del home ({e}). No se ha borrado nada.")
    if acc.process_count(name):
        _kill(ctx, name)
    if system.has_cmd("crontab"):
        system.run(["crontab", "-r", "-u", name])
    for f in {_sudo_file(name), _legacy_sudo_file(name)}:
        f.unlink(missing_ok=True)
    if not apply(ctx, "eliminar_usuario", name, ["userdel", "-r", name], f"copia_home={copy or 'ninguna'}"):
        return False
    ctx.out.ok(f"Usuario {name} eliminado.")
    return True


# ------------------------------------------------------------------ grupos y sudo

def grupo_add(ctx: Context, v: dict) -> bool:
    name, g = v["usuario"], v["grupo"]
    if not acc.user(name):
        return _err(ctx, f"No existe el usuario '{name}'")
    if not acc.group(g):
        return _err(ctx, f"No existe el grupo '{g}'")
    if acc.is_member(name, g):
        ctx.out.info(f"{name} ya está en {g}")
        return True
    if g in acc.priv_groups():
        ctx.out.warn(f"'{g}' es un grupo privilegiado")
    ok = apply(ctx, "anadir_a_grupo", name, ["gpasswd", "-a", name, g], f"grupo={g}", quiet=True)
    if ok:
        ctx.out.ok(f"{name} añadido a {g} (efectivo en su próximo inicio de sesión)")
    return ok


def grupo_del(ctx: Context, v: dict) -> bool:
    name, g = v["usuario"], v["grupo"]
    if not acc.user(name) or not acc.group(g):
        return _err(ctx, "El usuario o el grupo no existen")
    if acc.primary_group(name) == g:
        return _err(ctx, f"{g} es el grupo principal de {name}; no se puede quitar")
    if not acc.is_member(name, g):
        ctx.out.info(f"{name} no está en {g}")
        return True
    ok = apply(ctx, "quitar_de_grupo", name, ["gpasswd", "-d", name, g], f"grupo={g}", quiet=True)
    if ok:
        ctx.out.ok(f"{name} quitado de {g} (sus sesiones abiertas lo conservan hasta cerrarlas)")
    return ok


def grupo_crear(ctx: Context, v: dict) -> bool:
    g = v["grupo"]
    if not acc.valid_name(g):
        return _err(ctx, "Nombre de grupo no válido")
    if acc.group(g):
        return _err(ctx, f"Ya existe '{g}'")
    return apply(ctx, "crear_grupo", g, ["groupadd", g]) and (ctx.out.ok(f"Grupo {g} creado") or True)


def grupo_eliminar(ctx: Context, v: dict) -> bool:
    g = acc.group(v["grupo"])
    if not g:
        return _err(ctx, f"No existe '{v['grupo']}'")
    if g.gr_gid < acc.GID_MIN:
        return _err(ctx, f"'{g.gr_name}' es un grupo de sistema (GID {g.gr_gid}); no se elimina desde aquí")
    users = [u.pw_name for u in acc.local_users(True) if u.pw_gid == g.gr_gid]
    if users:
        return _err(ctx, f"Es el grupo principal de: {', '.join(users)}. Cámbialo antes.")
    return apply(ctx, "eliminar_grupo", g.gr_name, ["groupdel", g.gr_name], f"miembros={','.join(g.gr_mem) or '-'}") \
        and (ctx.out.ok(f"Grupo {g.gr_name} eliminado") or True)


def _sudo_file(name: str) -> Path:
    """Fichero de la regla en sudoers.d. sudo ignora los ficheros cuyo nombre contiene un punto
    (o acaba en ~), así que los caracteres fuera de [A-Za-z0-9_-] se codifican (juan.perez -> juan_2eperez)."""
    safe = re.sub(r"[^A-Za-z0-9_-]", lambda m: f"_{ord(m.group()):02x}", name)
    return Path(f"/etc/sudoers.d/90-opsdeck-{safe}")


def _legacy_sudo_file(name: str) -> Path:
    """Nombre usado hasta 2.4.1 (sin codificar). Con un punto, sudo nunca lo leyó; se limpia al retirar."""
    return Path(f"/etc/sudoers.d/90-opsdeck-{name}")


def sudo_dar(ctx: Context, v: dict) -> bool:
    name, mode = v["usuario"], v["modo"]
    if not _guard(ctx, name):
        return False
    if acc.sudo_summary(name) != "no" and mode == "grupo":
        ctx.out.info(f"{name} ya tiene sudo:")
        for r in acc.sudo_rules(name):
            ctx.out.line("  " + r)
        return True
    if mode == "grupo":
        g = acc.admin_group()
        if not g:
            return _err(ctx, "No existe grupo sudo/wheel en este sistema; usa el modo 'regla'")
        ok = apply(ctx, "conceder_sudo", name, ["gpasswd", "-a", name, g], f"via=grupo:{g}", quiet=True)
    else:
        nopass = "NOPASSWD: " if mode == "nopasswd" else ""
        rule = f"# Gestionado por opsdeck ({system.operator()}, {time.strftime('%Y-%m-%d')})\n{name} ALL=(ALL:ALL) {nopass}ALL\n"
        with tempfile.NamedTemporaryFile("w", delete=False) as t:
            t.write(rule)
        if not system.run(["visudo", "-cf", t.name]).ok:
            os.unlink(t.name)
            return _err(ctx, "La regla generada no es válida")
        ok = apply(ctx, "conceder_sudo", name, ["install", "-o", "root", "-g", "root", "-m", "0440", t.name,
                                                str(_sudo_file(name))], f"via={_sudo_file(name)} modo={mode}")
        os.unlink(t.name)
        if ok and not system.run(["visudo", "-c"]).ok:
            _sudo_file(name).unlink(missing_ok=True)
            audit.record("conceder_sudo", name, "REVERTIDO", "visudo -c falló")
            return _err(ctx, "sudoers dejó de validar; regla retirada")
    if ok:
        ctx.out.ok(f"{name} tiene sudo ({mode}). Efectivo en su próximo inicio de sesión.")
    return ok


def sudo_quitar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name, allow_self=False):
        return False
    g = acc.admin_group()
    if g and acc.is_member(name, g):
        apply(ctx, "revocar_sudo", name, ["gpasswd", "-d", name, g], f"via=grupo:{g}", quiet=True)
    for f in sorted({_sudo_file(name), _legacy_sudo_file(name)}):
        if f.exists():
            apply(ctx, "revocar_sudo", name, ["rm", "-f", str(f)], f"via={f}")
    if acc.sudo_summary(name) == "no":
        ctx.out.ok(f"{name} ya no tiene sudo.")
    else:
        ctx.out.warn(f"{name} SIGUE teniendo sudo por otra vía:")
        for r in acc.sudo_rules(name):
            ctx.out.line("  " + r)
        ctx.out.line("  Sus grupos: " + ", ".join(acc.groups_of(name)))
    return True


# ------------------------------------------------------------------ claves SSH

KEY_RE = r"(?:^|\s)(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)\s+(AAAA[A-Za-z0-9+/=]+)(?:\s+(.*))?$"


def _keys_file(name: str) -> Path:
    return Path(acc.user(name).pw_dir) / ".ssh" / "authorized_keys"


def _unsafe_ssh(name: str) -> str:
    home = Path(acc.user(name).pw_dir)
    for p in (home / ".ssh", home / ".ssh" / "authorized_keys"):
        if p.is_symlink():
            return f"{p} es un enlace simbólico: no se toca (revísalo a mano)"
    return ""


class _UnsafeSSH(Exception):
    pass


def _ssh_dir_fd(u, create: bool = False) -> int:
    """Abre ~/.ssh sin seguir enlaces. El usuario es dueño de la carpeta y podría cambiarla por un
    enlace entre la comprobación y la escritura; trabajar sobre el descriptor evita esa carrera."""
    home = os.open(u.pw_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if create:
            try:
                os.mkdir(".ssh", 0o700, dir_fd=home)
            except FileExistsError:
                pass
        try:
            d = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        except FileNotFoundError:
            raise
        except OSError as e:
            raise _UnsafeSSH(f"{u.pw_dir}/.ssh no es una carpeta normal: no se toca (revísalo a mano)") from e
    finally:
        os.close(home)
    st = os.fstat(d)
    if st.st_uid not in (0, u.pw_uid):
        os.close(d)
        raise _UnsafeSSH(f"{u.pw_dir}/.ssh pertenece a otro usuario: no se toca (revísalo a mano)")
    return d


def _check_keys_fd(fd: int, u) -> None:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid not in (0, u.pw_uid):
        raise _UnsafeSSH(f"{u.pw_dir}/.ssh/authorized_keys no es un fichero normal del usuario: "
                         "no se toca (revísalo a mano)")


def _read_keys(u) -> str:
    try:
        d = _ssh_dir_fd(u)
    except FileNotFoundError:
        return ""
    try:
        try:
            fd = os.open("authorized_keys", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=d)
        except FileNotFoundError:
            return ""
        except OSError as e:
            raise _UnsafeSSH(f"{u.pw_dir}/.ssh/authorized_keys es un enlace o no se puede abrir") from e
        with open(fd, encoding="utf-8", errors="replace") as fh:
            _check_keys_fd(fh.fileno(), u)
            return fh.read()
    finally:
        os.close(d)


def _key_lines(name: str) -> list[str]:
    try:
        text = _read_keys(acc.user(name))
    except (_UnsafeSSH, OSError):
        return []
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _append_key(u, key: str) -> None:
    d = _ssh_dir_fd(u, create=True)
    try:
        os.fchown(d, u.pw_uid, u.pw_gid)
        os.fchmod(d, 0o700)
        try:
            fd = os.open("authorized_keys", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=d)
        except OSError as e:
            raise _UnsafeSSH(f"{u.pw_dir}/.ssh/authorized_keys es un enlace o no se puede abrir") from e
        with open(fd, "a", encoding="utf-8") as fh:
            _check_keys_fd(fh.fileno(), u)
            os.fchown(fh.fileno(), u.pw_uid, u.pw_gid)
            os.fchmod(fh.fileno(), 0o600)
            fh.write(key + "\n")
    finally:
        os.close(d)


def _rewrite_keys(u, text: str) -> None:
    """Escribe un fichero nuevo y lo cambia por el antiguo dentro de la misma carpeta abierta."""
    d = _ssh_dir_fd(u)
    tmp = f".authorized_keys.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=d)
        try:
            with open(fd, "w", encoding="utf-8") as fh:
                os.fchown(fh.fileno(), u.pw_uid, u.pw_gid)
                fh.write(text)
            os.replace(tmp, "authorized_keys", src_dir_fd=d, dst_dir_fd=d)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=d)
            except OSError:
                pass
            raise
    finally:
        os.close(d)


def _fingerprint(line: str) -> str:
    if not system.has_cmd("ssh-keygen"):
        m = re.search(KEY_RE, line)
        return f"{m.group(1)} {m.group(3) or ''}" if m else "(no reconocida)"
    r = system.run(["ssh-keygen", "-lf", "-"], input=line + "\n")
    return r.out.strip() or "(no reconocida)"


def ssh_listar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not acc.user(name):
        return _err(ctx, f"No existe '{name}'")
    lines = _key_lines(name)
    if not lines:
        ctx.out.info(f"{name} no tiene claves SSH autorizadas.")
        return True
    f = _keys_file(name)
    st = f.stat()
    ctx.out.title(f"Claves SSH de {name} ({f}, permisos {oct(st.st_mode)[-3:]})")
    ctx.out.table(["Nº", "Huella / tipo / comentario"], [[str(i + 1), _fingerprint(l)] for i, l in enumerate(lines)])
    if st.st_mode & 0o077:
        ctx.out.warn("authorized_keys debería tener permisos 600.")
    return True


def ssh_anadir(ctx: Context, v: dict) -> bool:
    name, key = v["usuario"], v["clave"].strip()
    if not _guard(ctx, name):
        return False
    if os.path.isfile(key):
        key = next((l.strip() for l in Path(key).read_text(errors="replace").splitlines()
                    if l.strip() and not l.startswith("#")), "")
    m = re.search(KEY_RE, key)
    if not m or "\n" in key:
        return _err(ctx, "No parece una clave pública SSH (ssh-ed25519 AAAA... comentario)")
    fp = _fingerprint(key)
    if "(no reconocida)" in fp:
        return _err(ctx, "ssh-keygen no reconoce la clave")
    if m.group(1) == "ssh-rsa" and fp.split()[0].isdigit() and int(fp.split()[0]) < 3072:
        ctx.out.warn(f"Clave RSA de {fp.split()[0]} bits: mejor ed25519 o RSA de 3072 o más.")
    if any(m.group(2) in l for l in _key_lines(name)):
        ctx.out.info("Esa clave ya estaba autorizada.")
        return True
    problem = _unsafe_ssh(name)
    if problem:
        return _err(ctx, problem)
    try:
        _append_key(acc.user(name), key)
    except (_UnsafeSSH, OSError) as e:
        return _err(ctx, str(e))
    audit.record("anadir_clave_ssh", name, "OK", fp)
    ctx.out.ok(f"Clave añadida a {name}: {fp}")
    return True


def ssh_quitar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name):
        return False
    lines = _key_lines(name)
    try:
        n = int(v["numero"])
    except ValueError:
        return _err(ctx, "Indica el número de la clave (míralo en 'Ver claves SSH')")
    if not 1 <= n <= len(lines):
        return _err(ctx, f"{name} tiene {len(lines)} claves; no existe la número {n}")
    problem = _unsafe_ssh(name)
    if problem:
        return _err(ctx, problem)
    target = lines[n - 1]
    u = acc.user(name)
    try:
        kept = [l for l in _read_keys(u).splitlines() if l != target]
        _rewrite_keys(u, "\n".join(kept) + ("\n" if kept else ""))
    except (_UnsafeSSH, OSError) as e:
        return _err(ctx, str(e))
    audit.record("quitar_clave_ssh", name, "OK", _fingerprint(target))
    ctx.out.ok(f"Clave {n} eliminada de {name}.")
    return True


# ------------------------------------------------------------------ política e inventario

def politica(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    if not _guard(ctx, name):
        return False
    vals = {k: str(v.get(k, "")).strip() for k in ("minimo", "maximo", "aviso", "gracia")}
    for k, val in vals.items():
        if not val.lstrip("-").isdigit():
            return _err(ctx, f"'{k}' debe ser un número")
    ok = apply(ctx, "politica_password", name,
               ["chage", "-m", vals["minimo"], "-M", vals["maximo"], "-W", vals["aviso"], "-I", vals["gracia"], name],
               " ".join(f"{k}={x}" for k, x in vals.items()))
    if ok:
        ctx.out.ok(f"Política aplicada a {name}: caduca cada {vals['maximo']} días"
                   if vals["maximo"] != "99999" else f"Política aplicada a {name}: la contraseña no caduca")
    return ok


def inventario(ctx: Context, v: dict) -> bool:
    import csv
    paths.ensure_private_dir(paths.DATA_DIR, 0o750)
    paths.ensure_private_dir(paths.REPORT_DIR, 0o750)
    dest = paths.REPORT_DIR / f"inventario_usuarios_{system.hostname()}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    count = 0
    with open(dest, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["equipo", "usuario", "uid", "nombre", "grupo_principal", "grupos", "shell", "home", "estado",
                    "ultimo_cambio_password", "dias_validez", "caduca_cuenta", "sudo", "claves_ssh", "ultimo_login"])
        for u in acc.local_users(include_system=v.get("todos", False)):
            s = acc.shadow(u.pw_name) or [""] * 9
            w.writerow([system.hostname(), u.pw_name, u.pw_uid, u.pw_gecos, acc.primary_group(u.pw_name),
                        ",".join(acc.groups_of(u.pw_name)), u.pw_shell, u.pw_dir, acc.state(u.pw_name),
                        "forzado" if s[2] == "0" else acc.day2date(s[2]), s[4] or "-", acc.day2date(s[7]),
                        acc.sudo_summary(u.pw_name), len(_key_lines(u.pw_name)), acc.last_login(u.pw_name)])
            count += 1
    os.chmod(dest, 0o640)
    audit.record("exportar_inventario", system.hostname(), "OK", str(dest))
    ctx.out.ok(f"Inventario de {count} cuentas: {dest}")
    ctx.out.info("Separador ';' para abrirlo directamente en Excel o LibreOffice.")
    return True


# ------------------------------------------------------------------ definición

PASS_MODES = [("generar", "Generar una aleatoria (recomendado)"), ("manual", "Escribirla yo"),
              ("ninguna", "Ninguna por ahora (cuenta sin acceso)")]


class Usuarios(Module):
    id = "usuarios"
    name = "Usuarios"
    category = "Sistemas"
    summary = "Cuentas locales, contraseñas, grupos, sudo y sesiones"
    requires = [cmd("useradd", debian="passwd", rhel="shadow-utils", suse="shadow", arch="shadow"),
                cmd("chpasswd", debian="passwd", rhel="shadow-utils", suse="shadow", arch="shadow"),
                cmd("gpasswd", debian="passwd", rhel="shadow-utils", suse="shadow", arch="shadow")]
    help = """\
# Usuarios

Gestión de las **cuentas locales** de este equipo (las de `/etc/passwd`).
Las cuentas de dominio (Active Directory) se gestionarán en el módulo de Dominio.

## Estados de una cuenta
| Estado | Qué significa |
|---|---|
| activa | Puede entrar con su contraseña |
| debe-cambiar | Tiene que cambiar la contraseña al entrar. **Por escritorio remoto no puede**: que entre antes por SSH, o usa *Quitar cambio obligatorio* |
| bloqueada | Bloqueada, o creada sin contraseña |
| caducada | La cuenta ha pasado su fecha de caducidad |
| SIN-CLAVE | Entra **sin contraseña**: corrígelo cuanto antes |

## Buenas prácticas
- Crea las contraseñas con *Generar*: se muestran una sola vez y no se guardan.
- Para quitar el acceso a alguien, mejor **Bloquear** que Eliminar: se puede deshacer.
- Antes de eliminar, la herramienta guarda una copia de su carpeta personal.
- Cada cambio queda registrado (quién, qué y cuándo) y antes se copia
  `passwd/shadow/group/sudoers` por si hubiera que deshacerlo.

## Protecciones
No permite bloquear, eliminar ni quitar sudo a **tu propia cuenta**, ni tocar root o
las cuentas de sistema.
"""

    GROUPS = {
        "Consultar": ["listar", "listar_todos", "ficha", "sesiones"],
        "Cuentas": ["crear", "bloquear", "desbloquear", "eliminar", "caducidad", "cerrar"],
        "Contraseñas": ["password", "forzar", "quitar_cambio", "politica"],
        "Grupos": ["grupo_add", "grupo_del", "grupo_crear", "grupo_eliminar"],
        "Administradores (sudo)": ["sudo_ver", "sudo_dar", "sudo_quitar"],
        "Claves SSH": ["ssh_ver", "ssh_anadir", "ssh_quitar"],
        "Informes": ["inventario"],
    }

    def actions(self):
        by_id = {a.id: a for a in self._actions()}
        ordered = []
        for group, ids in self.GROUPS.items():
            for i in ids:
                a = by_id.pop(i)
                a.group = group
                ordered.append(a)
        return ordered + list(by_id.values())

    def _actions(self):
        u = Param("usuario", "Usuario", "user", help="Nombre de la cuenta local.")
        modo = Param("modo", "Contraseña", "choice", "generar", choices=PASS_MODES,
                     help="Generar crea una contraseña segura y te la muestra una vez.")
        pw = Param("password", "Contraseña (si eliges escribirla)", "password", required=False,
                   help=f"Mínimo {settings().get('usuarios', 'minimo_password')} caracteres.")
        return [
            Action("listar", "Listar usuarios", listar,
                   help="Cuentas de personas (y root) con su estado, último cambio de contraseña y grupos."),
            Action("listar_todos", "Listar todas las cuentas (incl. sistema)", lambda c, v: listar(c, {"todos": True}),
                   help="Incluye las cuentas de servicios del sistema (www-data, postgres...)."),
            Action("ficha", "Ficha de un usuario", ficha, params=[u],
                   help="Todo sobre una cuenta: grupos, estado, último acceso, sesiones, sudo y caducidad."),
            Action("crear", "Crear usuario", crear, changes=True, params=[
                Param("usuario", "Nombre de usuario", help="Minúsculas, números, _ y -. Ej.: jperez"),
                Param("nombre", "Nombre completo", required=False),
                Param("shell", "Shell", default=settings().get("usuarios", "shell"), required=False),
                Param("grupos", "Grupos adicionales (separados por coma)", "text", "", required=False,
                      help="Ej.: sudo para administradores. Deben existir."),
                Param("caduca", "Caducidad (AAAA-MM-DD, vacío = nunca)", required=False,
                      help="Útil para cuentas temporales."),
                modo, pw,
                Param("forzar", "Obligar a cambiarla en el primer inicio", "bool", True, required=False,
                      help="Desmárcalo si va a entrar por escritorio remoto: xrdp no sabe pedir el cambio."),
            ], help="Crea la cuenta con su carpeta personal y le asigna contraseña."),
            Action("bloquear", "Bloquear usuario", bloquear, changes=True,
                   params=[u, Param("cerrar", "Cerrar también sus sesiones abiertas", "bool", False, required=False)],
                   confirm="Se bloqueará {usuario}: no podrá entrar ni con contraseña ni con clave SSH. ¿Continuar?",
                   help="Impide el acceso sin borrar nada. Se deshace con Desbloquear."),
            Action("desbloquear", "Desbloquear usuario", desbloquear, changes=True, params=[u],
                   help="Devuelve el acceso a una cuenta bloqueada o caducada."),
            Action("eliminar", "Eliminar usuario", eliminar, changes=True, params=[
                u, Param("copia", "Guardar copia de su carpeta personal", "bool", True, required=False),
                Param("confirmacion", "Escribe otra vez el nombre para confirmar", help="Medida de seguridad."),
            ], confirm="Se ELIMINARÁ {usuario} con su carpeta personal, correo y tareas programadas. ¿Continuar?",
                help="Borra la cuenta. Antes guarda copia de su home (si lo dejas marcado)."),
            Action("password", "Restablecer contraseña", restablecer, changes=True, params=[
                u, modo, pw, Param("forzar", "Obligar a cambiarla al entrar", "bool", True, required=False)],
                help="Asigna una contraseña nueva, generada o escrita por ti."),
            Action("forzar", "Obligar a cambiar la contraseña", forzar, changes=True, params=[u],
                   help="La pedirá cambiar en su próximo inicio de sesión (no funciona por escritorio remoto)."),
            Action("quitar_cambio", "Quitar cambio obligatorio", quitar_cambio, changes=True, params=[u],
                   help="Para quien no puede entrar por escritorio remoto por tener el cambio pendiente."),
            Action("caducidad", "Caducidad de la cuenta", caducidad, changes=True, params=[
                u, Param("fecha", "Fecha (AAAA-MM-DD) o 'nunca'", default="nunca")],
                help="A partir de esa fecha la cuenta deja de funcionar."),
            Action("sesiones", "Sesiones abiertas", sesiones, help="Quién está conectado ahora (SSH, consola y RDP)."),
            Action("cerrar", "Cerrar sesiones de un usuario", cerrar_sesiones, changes=True, params=[u],
                   confirm="Se cerrarán TODAS las sesiones y procesos de {usuario}. ¿Continuar?",
                   help="Expulsa al usuario de todas sus sesiones."),
            Action("grupo_add", "Añadir usuario a un grupo", grupo_add, changes=True,
                   params=[u, Param("grupo", "Grupo", "group")], help="Da los permisos de ese grupo."),
            Action("grupo_del", "Quitar usuario de un grupo", grupo_del, changes=True,
                   params=[u, Param("grupo", "Grupo", "group")]),
            Action("grupo_crear", "Crear grupo", grupo_crear, changes=True, params=[Param("grupo", "Nombre del grupo")]),
            Action("grupo_eliminar", "Eliminar grupo", grupo_eliminar, changes=True,
                   params=[Param("grupo", "Grupo", "group")],
                   confirm="Se eliminará el grupo {grupo}. ¿Continuar?"),
            Action("sudo_ver", "Quién tiene sudo", quien_sudo,
                   help="Usuarios con permisos de administrador y reglas de sudoers."),
            Action("sudo_dar", "Dar sudo", sudo_dar, changes=True, params=[u, Param(
                "modo", "Cómo", "choice", "grupo", choices=[
                    ("grupo", "Añadir al grupo de administradores (recomendado)"),
                    ("regla", "Regla propia que pide contraseña"),
                    ("nopasswd", "Regla propia SIN contraseña (desaconsejado)")])],
                help="Convierte la cuenta en administradora del equipo."),
            Action("sudo_quitar", "Quitar sudo", sudo_quitar, changes=True, params=[u],
                   help="Retira el grupo de administradores y la regla propia; avisa si conserva sudo por otra vía."),
            Action("ssh_ver", "Ver claves SSH", ssh_listar, params=[u],
                   help="Claves públicas con las que el usuario puede entrar por SSH sin contraseña."),
            Action("ssh_anadir", "Añadir clave SSH", ssh_anadir, changes=True, params=[u, Param(
                "clave", "Clave pública (o ruta a un fichero .pub)",
                help="La línea completa: ssh-ed25519 AAAA... comentario")],
                help="Autoriza una clave pública. Comprueba que es válida y crea ~/.ssh con los permisos correctos."),
            Action("ssh_quitar", "Quitar clave SSH", ssh_quitar, changes=True, params=[u, Param(
                "numero", "Número de la clave", "int", help="Míralo antes en 'Ver claves SSH'.")],
                confirm="Se quitará la clave {numero} de {usuario}. ¿Continuar?"),
            Action("politica", "Política de caducidad de contraseña", politica, changes=True, params=[
                u, Param("maximo", "Días de validez (99999 = no caduca)", "int", 90),
                Param("minimo", "Días mínimos entre cambios", "int", 1),
                Param("aviso", "Días de aviso antes de caducar", "int", 7),
                Param("gracia", "Días de gracia tras caducar (-1 = sin límite)", "int", 14)],
                help="Cada cuánto debe cambiar la contraseña y qué pasa si no lo hace."),
            Action("inventario", "Exportar inventario (CSV)", inventario, params=[
                Param("todos", "Incluir cuentas de sistema", "bool", False, required=False)],
                help="Hoja con todas las cuentas: estado, grupos, sudo, claves, último acceso."),
        ]
