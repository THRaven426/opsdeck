"""Escritorio remoto (xrdp): estado, diagnóstico de por qué alguien no entra, y control de acceso.

Funcionamiento de xrdp que hay que tener en cuenta (verificado en /etc/xrdp/sesman.ini):
- Si existe el grupo TerminalServerUsers (tsusers por defecto) solo entran sus miembros.
- Si no existe, entra cualquiera con contraseña, salvo AlwaysGroupCheck=true (nadie entra).
- El grupo se comprueba en cada inicio de sesión: no hace falta reiniciar xrdp.
- xrdp no sabe pedir un cambio de contraseña obligatorio: el inicio falla."""

from __future__ import annotations

import re
from pathlib import Path

from ..core import accounts as acc
from ..core import safeio, system
from ..core.catalog import Action, Context, Module, Param, cmd, file
from ..core.ops import apply

SESMAN = Path("/etc/xrdp/sesman.ini")


def ini_get(section: str, key: str) -> str:
    cur = ""
    try:
        for raw in SESMAN.read_text(errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1]
            elif cur == section and "=" in line and not line.startswith((";", "#")):
                k, v = line.split("=", 1)
                if k.strip() == key:
                    return v.strip()
    except OSError:
        pass
    return ""


def rdp_group() -> str:
    return ini_get("Security", "TerminalServerUsers") or "tsusers"


def _true(v: str) -> bool:
    return v.lower() in ("true", "yes", "1", "on")


def mode() -> str:
    """grupo | abierto | cerrado"""
    if acc.group(rdp_group()):
        return "grupo"
    return "cerrado" if _true(ini_get("Security", "AlwaysGroupCheck")) else "abierto"


def root_allowed() -> bool:
    v = ini_get("Security", "AllowRootLogin")
    return v == "" or _true(v)


def active_users() -> list[str]:
    r = system.run(["ps", "-eo", "user:32=,comm="])
    return sorted({l.split()[0] for l in r.out.splitlines() if len(l.split()) == 2 and l.split()[1].startswith("xrdp-chansrv")})


def default_session() -> str:
    if not system.has_cmd("update-alternatives"):
        return ""
    r = system.run(["update-alternatives", "--query", "x-session-manager"], c_locale=True)
    m = re.search(r"^Value:\s*(\S+)", r.out, re.M)
    return m.group(1) if m else ""


def last_attempt(user: str) -> tuple[str, str]:
    """(veredicto, línea) del último intento de entrar por RDP según el journal."""
    if not system.has_cmd("journalctl"):
        return "", ""
    r = system.run(["journalctl", "-q", "--no-pager", "--since", "7 days ago",
                    "-t", "xrdp-sesexec", "-t", "unix_chkpwd", "-t", "xrdp-sesman"], timeout=30)
    pat = re.compile(rf"user[=: ]+\(?{re.escape(user)}\)?( |$)|for user {re.escape(user)} |for {re.escape(user)} ")
    lines = [l for l in r.out.splitlines()
             if pat.search(l) and "login status" not in l and "login request" not in l]
    if not lines:
        return "", ""
    last = lines[-1]
    if any(k in last for k in ("password check failed", "authentication failure", "AUTHFAIL")):
        return "contraseña", last
    if any(k in last for k in ("expired password", "new one required")):
        return "cambio", last
    if any(k.lower() in last.lower() for k in ("session started", "login successful")):
        return "ok", last
    return "otro", last


# ------------------------------------------------------------------ acciones

def estado(ctx: Context, v: dict) -> bool:
    g = rdp_group()
    m = mode()
    listen = system.run(["ss", "-ltnpH"], c_locale=True).out if system.has_cmd("ss") else ""
    addrs = " ".join(l.split()[3] for l in listen.splitlines() if "xrdp" in l) or "(no detectado)"
    rows = [
        ["Servicio xrdp", system.service_state("xrdp")],
        ["Servicio xrdp-sesman", system.service_state("xrdp-sesman")],
        ["Escuchando en", addrs],
        ["Quién puede entrar", {"grupo": f"solo el grupo '{g}'",
                                "abierto": "CUALQUIER usuario con contraseña",
                                "cerrado": "nadie (AlwaysGroupCheck=true sin grupo)"}[m]],
    ]
    if m == "grupo":
        rows.append(["Miembros", ", ".join(acc.group(g).gr_mem) or "(ninguno)"])
    rows += [["Entrar como root", "permitido" if root_allowed() else "no permitido"],
             ["Conectados ahora", ", ".join(active_users()) or "nadie"],
             ["Escritorio por defecto", default_session() or "ninguno configurado"]]
    ctx.out.title("Escritorio remoto (xrdp)")
    ctx.out.table(["Dato", "Valor"], rows)
    if m == "abierto":
        ctx.out.warn("Recomendado: 'Limitar el acceso a un grupo' para decidir quién entra.")
    if root_allowed():
        ctx.out.warn(f"Recomendado: poner AllowRootLogin=false en {SESMAN} (requiere reiniciar xrdp-sesman "
                     "desde SSH, no desde una sesión RDP).")
    return True


def diagnosticar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    u = acc.user(name)
    if not u:
        return ctx.out.error(f"No existe '{name}'") or False
    g, m, st = rdp_group(), mode(), acc.state(name)
    o = ctx.out
    o.title(f"¿Puede {name} entrar por escritorio remoto?")
    problems = []
    if m == "grupo":
        ok = acc.is_member(name, g)
        o.check(ok, f"Está en el grupo '{g}'" if ok else f"No está en el grupo '{g}' (solo sus miembros entran)")
        if not ok:
            problems.append("Usa 'Dar acceso' en este módulo.")
    elif m == "abierto":
        o.check(True, "El acceso está abierto: no necesita grupo")
    else:
        o.check(False, "Nadie puede entrar: AlwaysGroupCheck=true y no existe el grupo")
        problems.append("Usa 'Limitar el acceso a un grupo' para crearlo.")
    if st == "activa":
        o.check(True, "Cuenta activa y contraseña vigente")
    elif st in ("debe-cambiar", "pass-caducada"):
        o.check(False, "Tiene que cambiar la contraseña: xrdp no puede pedirlo y el inicio falla")
        problems.append("Que entre una vez por SSH y la cambie, o usa Usuarios > 'Quitar cambio obligatorio'.")
    else:
        o.check(False, f"Estado de la cuenta: {st}")
        problems.append("Revisa la cuenta en Usuarios (desbloquear / restablecer contraseña).")
    shell_ok = not u.pw_shell.endswith(("nologin", "false"))
    o.check(shell_ok, f"Shell {u.pw_shell}")
    home_ok = Path(u.pw_dir).is_dir()
    o.check(home_ok, f"Carpeta personal {u.pw_dir}" + ("" if home_ok else " no existe"))
    xs = Path(u.pw_dir, ".xsession")
    if xs.is_symlink():
        o.check(False, f"~/.xsession es un enlace simbólico a {xs.resolve()}: revísalo a mano")
    elif xs.exists():
        try:
            first = (safeio.read_text(xs, 4096, owners=(0, u.pw_uid)).strip().splitlines() or ["(vacío)"])[0]
            o.check(True, f"~/.xsession: {first[:120]}")
        except OSError as e:
            o.check(False, f"~/.xsession no se puede leer de forma segura ({e}): revísalo a mano")
    else:
        d = default_session()
        o.check(bool(d), f"Sin ~/.xsession: usará el escritorio por defecto ({d})" if d
                else "Sin ~/.xsession y sin escritorio por defecto: puede quedarse en negro")
    if u.pw_uid == 0 and not root_allowed():
        o.check(False, "AllowRootLogin=false: root no puede entrar por RDP")
    verdict, line = last_attempt(name)
    stamp = line[:15]
    if verdict == "contraseña":
        o.check(False, f"Último intento ({stamp}): CONTRASEÑA INCORRECTA")
        problems.append("Que compruebe la contraseña o restablécela en Usuarios.")
    elif verdict == "cambio":
        o.check(False, f"Último intento ({stamp}): rechazado por cambio de contraseña obligatorio")
    elif verdict == "ok":
        o.check(True, f"Último intento ({stamp}): correcto")
    elif verdict == "otro":
        o.line(f"  Último registro: {line}")
    else:
        o.info("Sin intentos de RDP en los últimos 7 días.")
    if problems:
        o.title("Qué hacer")
        for p in dict.fromkeys(problems):
            o.line("  • " + p)
    else:
        o.ok("No veo impedimentos. Si aun así falla: que no tenga a la vez una sesión gráfica abierta en la consola.")
    return True


def _restrict_members(include: str = "", exclude: str = "") -> list[str]:
    names = []
    for n in [system.operator(), *active_users(), include]:
        if n and n != "root" and n != exclude and acc.user(n) and n not in names:
            names.append(n)
    return names


def limitar(ctx: Context, v: dict) -> bool:
    g = rdp_group()
    if mode() == "grupo":
        ctx.out.info(f"El acceso ya está limitado al grupo '{g}'. Usa 'Dar acceso' / 'Quitar acceso'.")
        return True
    members = _restrict_members(v.get("usuario", ""))
    if not apply(ctx, "limitar_rdp", g, ["groupadd", g], f"miembros={','.join(members) or '-'}"):
        return False
    for n in members:
        apply(ctx, "conceder_rdp", n, ["gpasswd", "-a", n, g], f"grupo={g}", quiet=True)
    ctx.out.ok(f"Escritorio remoto limitado al grupo '{g}': {', '.join(members) or 'nadie'}. "
               "Se aplica en el próximo inicio de sesión, sin reiniciar xrdp.")
    return True


def dar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    why = acc.guard(name)
    if why:
        return ctx.out.error(why) or False
    g = rdp_group()
    m = mode()
    if m == "abierto":
        ctx.out.info(f"El acceso está abierto: {name} ya puede entrar. Si quieres controlar quién entra, "
                     "usa 'Limitar el acceso a un grupo'.")
    elif m == "cerrado":
        ctx.out.warn("Ahora no puede entrar nadie. Usa 'Limitar el acceso a un grupo' incluyendo a este usuario.")
        return False
    elif acc.is_member(name, g):
        ctx.out.info(f"{name} ya está en '{g}'.")
    elif not apply(ctx, "conceder_rdp", name, ["gpasswd", "-a", name, g], f"grupo={g}", quiet=True):
        return False
    else:
        ctx.out.ok(f"{name} añadido a '{g}'.")
    return diagnosticar(ctx, {"usuario": name})


def quitar(ctx: Context, v: dict) -> bool:
    name = v["usuario"]
    why = acc.guard(name, allow_self=False)
    if why:
        return ctx.out.error(why) or False
    g, m = rdp_group(), mode()
    if m == "abierto":
        ctx.out.warn("El acceso está abierto a todos: para quitárselo a alguien primero hay que "
                     "'Limitar el acceso a un grupo'.")
        return False
    if m == "grupo" and acc.is_member(name, g):
        if not apply(ctx, "revocar_rdp", name, ["gpasswd", "-d", name, g], f"grupo={g}", quiet=True):
            return False
        ctx.out.ok(f"{name} ya no puede iniciar sesión por escritorio remoto.")
    else:
        ctx.out.info(f"{name} no tenía acceso.")
    if name in active_users():
        ctx.out.warn(f"{name} tiene una sesión abierta y la conserva hasta cerrarla "
                     "(Usuarios > 'Cerrar sesiones de un usuario').")
    return True


def _limit_confirm(v: dict) -> str:
    if mode() == "grupo":
        return ""
    members = _restrict_members(v.get("usuario", ""))
    return (f"Se creará el grupo '{rdp_group()}' y SOLO podrán entrar por escritorio remoto: "
            f"{', '.join(members) or 'nadie'}. El resto quedará fuera. ¿Continuar?")


class EscritorioRemoto(Module):
    id = "rdp"
    name = "Escritorio remoto"
    category = "Sistemas"
    summary = "Acceso por RDP (xrdp): quién entra y por qué alguien no puede"
    requires = [cmd("xrdp-sesman", debian="xrdp", rhel="xrdp", suse="xrdp", label="servidor xrdp"),
                file(str(SESMAN), debian="xrdp", rhel="xrdp", suse="xrdp", label="configuración de xrdp")]
    help = """\
# Escritorio remoto (xrdp)

Permite entrar al escritorio de este equipo desde Windows (*Conexión a Escritorio remoto*)
u otros clientes RDP. Este módulo solo aparece si xrdp está instalado.

## Quién puede entrar
- **Abierto** (lo normal al instalar xrdp): cualquier usuario con contraseña.
- **Limitado a un grupo** (recomendado): solo los miembros del grupo `tsusers`.
  Se activa con *Limitar el acceso a un grupo*; la herramienta incluye primero a quien
  esté conectado ahora y a ti, para que nadie se quede fuera sin querer.

## "No puedo entrar": causas habituales
1. **Cambio de contraseña obligatorio**: xrdp no sabe pedirlo. Que entre una vez por SSH y la cambie,
   o usa *Usuarios > Quitar cambio obligatorio*.
2. **Contraseña incorrecta**: el diagnóstico lo detecta en el registro del sistema.
3. **No está en el grupo** (si el acceso está limitado).
4. **Cuenta bloqueada o caducada**.

*Diagnosticar un usuario* revisa todo esto y te dice qué hacer.

## Seguridad
- Por defecto xrdp permite entrar como root. Cámbialo a `AllowRootLogin=false` en
  `/etc/xrdp/sesman.ini` y reinicia `xrdp-sesman` **desde SSH** (reiniciar desde una sesión RDP la corta).
- En los registros, las conexiones que pasan por un firewall con NAT aparecen con la IP del firewall.
"""

    def actions(self):
        u = Param("usuario", "Usuario", "user")
        return [
            Action("estado", "Estado y quién puede entrar", estado,
                   help="Servicios, modo de acceso, miembros, conectados ahora y recomendaciones."),
            Action("diagnosticar", "Diagnosticar un usuario", diagnosticar, params=[u],
                   help="Comprueba todo lo que puede impedir entrar y lee el motivo del último intento."),
            Action("dar", "Dar acceso", dar, changes=True, params=[u],
                   help="Si el acceso está limitado a un grupo, añade al usuario. Después hace el diagnóstico."),
            Action("quitar", "Quitar acceso", quitar, changes=True, params=[u],
                   help="Saca al usuario del grupo de escritorio remoto."),
            Action("limitar", "Limitar el acceso a un grupo", limitar, changes=True,
                   params=[Param("usuario", "Incluir además a", "user", required=False)],
                   confirm=_limit_confirm,
                   help="Crea el grupo de acceso. Incluye a quien esté conectado y a ti para no dejar a nadie fuera."),
        ]
