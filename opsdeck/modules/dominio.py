"""Dominio: unir el equipo a Active Directory (realmd + sssd), controlar quién entra y quién es administrador.

Flujo de unión: comprobaciones previas (DNS del dominio, hora sincronizada) -> realm join con la
contraseña por stdin -> carpeta personal automática -> nombres cortos opcionales -> grupos permitidos
-> sudo para un grupo del dominio (validado con visudo)."""

from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path

from ..core import audit, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import apply

DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
GROUP_RE = re.compile(r"^[^\x00-\x1f:,=@\\/\"]{1,120}$")
SSSD_CONF = Path("/etc/sssd/sssd.conf")


def realm_list() -> list[dict]:
    """Dominios configurados según 'realm list'."""
    r = system.run(["realm", "list"], c_locale=True)
    domains, cur = [], None
    for line in r.out.splitlines():
        if line and not line.startswith(" "):
            cur = {"nombre": line.strip()}
            domains.append(cur)
        elif cur is not None and ":" in line:
            k, v = line.strip().split(":", 1)
            cur.setdefault(k.strip(), []).append(v.strip()) if k.strip() in ("permitted-logins", "permitted-groups") \
                else cur.__setitem__(k.strip(), v.strip())
    return domains


def joined() -> dict:
    return next((d for d in realm_list() if d.get("configured", "no") != "no"), {})


def _time_synced() -> str:
    if system.has_cmd("timedatectl"):
        r = system.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], c_locale=True)
        if r.ok:
            return "si" if r.out.strip() == "yes" else "no"
    return "desconocido"


def _short_names(domain: str) -> bool:
    try:
        text = SSSD_CONF.read_text()
    except OSError:
        return False
    sec = re.search(rf"^\[domain/{re.escape(domain)}\](.*?)(?=^\[|\Z)", text, re.M | re.S | re.I)
    return bool(sec and re.search(r"^\s*use_fully_qualified_names\s*=\s*false", sec.group(1), re.M | re.I))


def _ad_group_ref(group: str, domain: str) -> str:
    """Cómo se escribe el grupo en sudoers: %nombre o %nombre@dominio, escapando espacios."""
    name = group if _short_names(domain) else f"{group}@{domain}"
    return "%" + name.replace(" ", "\\ ")


def estado(ctx: Context, v: dict) -> bool:
    d = joined()
    o = ctx.out
    if not d:
        o.info("Este equipo no está unido a ningún dominio.")
        o.check(_time_synced() == "si", f"Hora sincronizada con NTP: {_time_synced()} (Kerberos exige menos de 5 min de diferencia)")
        o.info("Para unirlo: 'Comprobar un dominio' y después 'Unir al dominio'.")
        return True
    o.title(f"Unido a {d['nombre']}")
    rows = [["Tipo", d.get("server-software", "?")], ["Software cliente", d.get("client-software", "?")],
            ["Quién puede entrar", {"allow-realm-logins": "todos los usuarios del dominio",
                                    "allow-permitted-logins": "solo los usuarios y grupos permitidos",
                                    "deny-any-login": "nadie del dominio"}.get(d.get("login-policy", ""), d.get("login-policy", "?"))],
            ["Usuarios permitidos", ", ".join(d.get("permitted-logins", [])) or "-"],
            ["Grupos permitidos", ", ".join(d.get("permitted-groups", [])) or "-"],
            ["Formato de nombre", d.get("login-formats", "?")],
            ["Servicio sssd", system.service_state("sssd")],
            ["Hora sincronizada", _time_synced()]]
    o.table(["Dato", "Valor"], rows)
    sudo = sorted(Path("/etc/sudoers.d").glob("90-opsdeck-ad-*"))
    if sudo:
        o.title("Grupos del dominio con sudo (gestionados por opsdeck)")
        for f in sudo:
            for line in f.read_text().splitlines():
                if line.strip() and not line.startswith("#"):
                    o.line("  " + line)
    return True


def comprobar(ctx: Context, v: dict) -> bool:
    dom = v["dominio"].strip().lower()
    if not DOMAIN_RE.match(dom):
        ctx.out.error("Nombre de dominio no válido (ej.: empresa.local)")
        return False
    o = ctx.out
    o.title(f"Comprobaciones para unir a {dom}")
    r = system.run(["realm", "discover", dom], c_locale=True, timeout=60)
    found = r.ok and r.out.strip()
    o.check(bool(found), "El dominio responde (DNS y LDAP)" if found else
            "No se encuentra el dominio: el DNS de este equipo debe apuntar a los controladores de dominio")
    if found:
        info = {l.split(":", 1)[0].strip(): l.split(":", 1)[1].strip() for l in r.out.splitlines() if ":" in l}
        o.line(f"    Tipo: {info.get('server-software', '?')}  ·  Paquetes que faltan: {info.get('required-package', 'ninguno')}")
    synced = _time_synced()
    o.check(synced == "si", f"Hora sincronizada: {synced}" + ("" if synced == "si" else
            " (Kerberos falla con más de 5 minutos de diferencia; configura NTP contra los controladores)"))
    d = joined()
    if d:
        o.check(False, f"Este equipo ya está unido a {d['nombre']}")
    if found and not d:
        o.ok("Se puede unir. Usa 'Unir al dominio' con una cuenta que pueda añadir equipos al dominio.")
    return bool(found)


def _sssd_section(text: str, section: str):
    sec = re.search(rf"^\[{re.escape(section)}\]\s*$", text, re.M | re.I)
    if not sec:
        return None
    nxt = re.search(r"^\[", text[sec.end():], re.M)
    return sec.end(), sec.end() + nxt.start() if nxt else len(text)


def sssd_get(section: str, key: str, default: str = "") -> str:
    try:
        text = SSSD_CONF.read_text()
    except OSError:
        return default
    span = _sssd_section(text, section)
    if not span:
        return default
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*)$", text[span[0]:span[1]], re.M)
    return m.group(1).strip() if m else default


def sssd_set(section: str, values: dict, create: bool = False) -> bool:
    """Cambia claves de una sección de sssd.conf conservando el resto (escritura atómica, 0600)."""
    try:
        text = SSSD_CONF.read_text()
    except OSError:
        return False
    span = _sssd_section(text, section)
    if not span:
        if not create:
            return False
        text = text.rstrip("\n") + f"\n\n[{section}]\n"
        span = _sssd_section(text, section)
    body = text[span[0]:span[1]]
    for key, val in values.items():
        if re.search(rf"^\s*{re.escape(key)}\s*=", body, re.M):
            body = re.sub(rf"^\s*{re.escape(key)}\s*=.*$", f"{key} = {val}", body, flags=re.M)
        else:
            body = body.rstrip("\n") + f"\n{key} = {val}\n"
    new = text[:span[0]] + body + text[span[1]:]
    with tempfile.NamedTemporaryFile("w", dir=str(SSSD_CONF.parent), delete=False) as t:
        t.write(new)
    os.chmod(t.name, 0o600)
    os.replace(t.name, SSSD_CONF)
    return True


def _sssd_short_names(ctx, dom: str) -> bool:
    if not sssd_set(f"domain/{dom}", {"use_fully_qualified_names": "False", "fallback_homedir": "/home/%u"}):
        ctx.out.warn(f"No se pudo ajustar {SSSD_CONF} (¿existe la sección del dominio?)")
        return False
    audit.record("dominio_nombres_cortos", dom, "OK")
    apply(ctx, "reiniciar_sssd", "sssd", ["systemctl", "restart", "sssd"], quiet=True)
    return True


GPO_MODES = [("enforcing", "Aplicarlas: las GPO de 'permitir/denegar inicio de sesión' mandan (por defecto)"),
             ("permissive", "Solo avisar en el registro, sin bloquear a nadie"),
             ("disabled", "Ignorarlas")]


def ajustes(ctx: Context, v: dict) -> bool:
    d = joined()
    if not d:
        ctx.out.error("El equipo no está unido a un dominio.")
        return False
    dom = d["nombre"]
    try:
        days = max(0, int(v.get("dias_offline") or 0))
    except ValueError:
        ctx.out.error("Los días deben ser un número")
        return False
    vals = {"cache_credentials": "True" if v.get("offline") else "False",
            "ad_gpo_access_control": v["gpo"],
            "dyndns_update": "True" if v.get("dns") else "False"}
    if not sssd_set(f"domain/{dom}", vals):
        ctx.out.error(f"No se pudo modificar {SSSD_CONF}")
        return False
    sssd_set("pam", {"offline_credentials_expiration": str(days)}, create=True)
    detail = " ".join(f"{k}={x}" for k, x in vals.items()) + f" offline_credentials_expiration={days}"
    audit.record("dominio_ajustes", dom, "OK", detail)
    apply(ctx, "reiniciar_sssd", "sssd", ["systemctl", "restart", "sssd"], quiet=True)
    ctx.out.ok("Ajustes aplicados y sssd reiniciado:")
    ctx.out.line(f"  Entrar sin conexión con el dominio: {'sí' if v.get('offline') else 'no'}"
                 + (f" (como mucho {days} días)" if v.get("offline") and days else ""))
    ctx.out.line(f"  Directivas de grupo de inicio de sesión: {v['gpo']}")
    ctx.out.line(f"  Registrar el equipo en el DNS del dominio: {'sí' if v.get('dns') else 'no'}")
    return True


def verificar(ctx: Context, v: dict) -> bool:
    d = joined()
    o = ctx.out
    if not d:
        o.error("El equipo no está unido a un dominio.")
        return False
    dom = d["nombre"]
    sec = f"domain/{dom}"
    todo = []
    o.title(f"Verificación de la unión a {dom}")
    st = system.service_state("sssd")
    o.check(st == "active", f"Servicio sssd: {st}")
    if st not in ("active", "desconocido"):
        todo.append("Arranca sssd en Servicios y mira su registro.")
    sync = _time_synced()
    o.check(sync == "si", f"Hora sincronizada: {sync}")
    if sync == "no":
        todo.append("Sincroniza la hora con los controladores de dominio (NTP): Kerberos falla con más de 5 min.")
    disc = system.run(["realm", "discover", dom], c_locale=True, timeout=60)
    o.check(disc.ok and bool(disc.out.strip()), "El dominio responde (DNS y LDAP)")
    kt = Path("/etc/krb5.keytab")
    if kt.exists():
        mode = kt.stat().st_mode & 0o777
        o.check(mode & 0o077 == 0, f"Clave del equipo (/etc/krb5.keytab) con permisos {oct(mode)[-3:]}")
        if mode & 0o077:
            todo.append("chmod 600 /etc/krb5.keytab: con esa clave se puede suplantar al equipo en el dominio.")
    else:
        o.check(False, "No existe /etc/krb5.keytab (la unión está incompleta)")
    if SSSD_CONF.exists():
        mode = SSSD_CONF.stat().st_mode & 0o777
        o.check(mode == 0o600, f"{SSSD_CONF} con permisos {oct(mode)[-3:]}")
        if mode != 0o600:
            todo.append(f"chmod 600 {SSSD_CONF} (sssd no arranca con otros permisos).")
    o.title("Quién puede entrar")
    policy = d.get("login-policy", "")
    open_all = policy == "allow-realm-logins"
    o.check(not open_all, "Acceso limitado a usuarios/grupos concretos" if not open_all
            else "Puede entrar CUALQUIER usuario del dominio")
    if open_all:
        todo.append("Limita el acceso con 'Permitir acceso' a los grupos que deban entrar.")
    else:
        o.line("    Permitidos: " + (", ".join(d.get("permitted-groups", []) + d.get("permitted-logins", [])) or "nadie"))
    gpo = sssd_get(sec, "ad_gpo_access_control", "enforcing (por defecto)")
    o.line(f"    Directivas de grupo de inicio de sesión: {gpo}")
    sudo = [l for f in sorted(Path("/etc/sudoers.d").glob("90-opsdeck-ad-*")) for l in f.read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    o.line("    Administradores (sudo) del dominio: " + ("; ".join(sudo) if sudo else "ninguno"))
    if not sudo:
        o.info("Sin un grupo del dominio con sudo, solo las cuentas locales administran este equipo.")
    o.title("Comodidad y resiliencia")
    pam = "".join(p.read_text(errors="replace") for p in (Path("/etc/pam.d/common-session"), Path("/etc/pam.d/system-auth"))
                  if p.exists())
    mk = "pam_mkhomedir" in pam or "pam_oddjob_mkhomedir" in pam
    o.check(mk, "La carpeta personal se crea sola al entrar" if mk else "No se crea la carpeta personal al entrar")
    if not mk:
        todo.append("Activa la creación de la carpeta personal (pam-auth-update --enable mkhomedir).")
    cache = sssd_get(sec, "cache_credentials", "False").lower() == "true"
    exp = sssd_get("pam", "offline_credentials_expiration", "0")
    o.line(f"    Entrar sin conexión con el dominio: {'sí' if cache else 'no'}"
           + (f" (máx. {exp} días)" if cache and exp != "0" else (" (sin límite de días)" if cache else "")))
    if cache and exp == "0":
        todo.append("Pon un límite de días al acceso sin conexión (acción 'Ajustes de seguridad'): "
                    "sin él, una cuenta desactivada en el AD seguiría entrando en un equipo aislado.")
    o.line(f"    Nombres cortos: {'sí' if _short_names(dom) else 'no (usuario@dominio)'}")
    o.line(f"    Registro en el DNS del dominio: {sssd_get(sec, 'dyndns_update', 'true (por defecto)')}")
    if todo:
        o.title("Qué conviene hacer")
        for t in todo:
            o.line("  • " + t)
    else:
        o.ok("La unión al dominio está bien configurada.")
    return True


AD_PKGS = [("sssd", "sssd"), ("realm", "realmd"), ("adcli", "adcli"), ("net", "samba-common-bin / samba-client"),
           ("klist", "krb5-user / krb5-workstation")]


def _fqdn_ok() -> tuple[bool, str]:
    r = system.run(["hostname", "-f"], c_locale=True)
    name = r.out.strip()
    return ("." in name, name or "(sin nombre)")


def _missing_pkgs() -> list[str]:
    return [pkg for binname, pkg in AD_PKGS if not system.has_cmd(binname)]


def revisar(ctx: Context, v: dict) -> bool:
    """Revisión única: si el equipo está unido, repasa su salud; si no, mira si está listo para unirse."""
    d = joined()
    if d:
        return verificar(ctx, v)
    dom = (v.get("dominio") or "").strip().lower()
    if not dom:
        guess = _domain_guess()
        dom = guess[0] if guess else ""
    if not dom:
        ctx.out.info("Este equipo no está unido a ningún dominio.")
        ctx.out.info("Indica el dominio para comprobar si está listo para unirse (DNS, hora, paquetes...).")
        return True
    ctx.out.info(f"Este equipo no está unido. Comprobando si está listo para unirse a {dom}:")
    ok = comprobar(ctx, {"dominio": dom})
    faltan = _missing_pkgs()
    fqdn_ok, fqdn = _fqdn_ok()
    ctx.out.check(not faltan, "Herramientas de dominio instaladas" if not faltan
                  else "Faltan herramientas de dominio: " + ", ".join(faltan) + " (instálalas desde el Catálogo)")
    ctx.out.check(fqdn_ok, f"Nombre completo del equipo: {fqdn}" if fqdn_ok
                  else f"El equipo no tiene nombre de dominio completo (FQDN): {fqdn}. Conviene ponerle uno (hostnamectl).")
    return ok


def _sshd_effective(key: str) -> str:
    """Valor efectivo de una opción de sshd (vía 'sshd -T'); '' si no se puede determinar."""
    r = system.run(["sshd", "-T"], c_locale=True)
    if not r.ok:
        return ""
    for line in r.out.splitlines():
        parts = line.split()
        if parts and parts[0].lower() == key.lower():
            return parts[1].lower() if len(parts) > 1 else ""
    return ""


def diagnosticar(ctx: Context, v: dict) -> bool:
    """Por qué un usuario del dominio no puede cambiar su contraseña caducada: revisa los 3 puntos típicos."""
    o = ctx.out
    o.title("Diagnóstico: cambiar una contraseña caducada del dominio")
    todo = []
    d = joined()
    if d:
        sec = f"domain/{d['nombre']}"
        chpass = sssd_get(sec, "chpass_provider", "") or sssd_get(sec, "auth_provider", "")
        ok = chpass in ("ad", "krb5")
        o.check(ok, f"SSSD chpass_provider = {chpass or 'no definido'} (debe ser 'ad' o 'krb5' para cambiarla contra el DC)")
        if not ok:
            todo.append(f"En {SSSD_CONF}, sección [{sec}], pon 'chpass_provider = ad' y reinicia sssd.")
    else:
        o.info("El equipo no está unido a un dominio; esto aplica a un equipo ya unido. Reviso igualmente el SSH.")
    kbd = _sshd_effective("kbdinteractiveauthentication") or _sshd_effective("challengeresponseauthentication")
    usepam = _sshd_effective("usepam")
    if not kbd and not usepam:
        o.check(False, "No se pudo leer la configuración efectiva de SSH (sshd -T). Revísala a mano.")
        todo.append("Comprueba en sshd_config: KbdInteractiveAuthentication yes y UsePAM yes.")
    else:
        ssh_ok = kbd == "yes" and usepam == "yes"
        o.check(ssh_ok, f"SSH interactivo: KbdInteractive={kbd or '?'}, UsePAM={usepam or '?'} "
                        "(ambos 'yes' para que el usuario pueda cambiarla al entrar por SSH)")
        if not ssh_ok:
            todo.append("En sshd_config: 'KbdInteractiveAuthentication yes' y 'UsePAM yes'; luego reinicia ssh. "
                        "Con solo PasswordAuthentication, al caducar la contraseña SSH corta y el usuario no puede cambiarla.")
    o.info("Tercer punto (política del dominio): si hay 'edad mínima de contraseña', una recién cambiada no se puede "
           "volver a cambiar hasta pasar ese plazo. Consulta la política completa del dominio en el módulo «LDAP».")
    if todo:
        o.title("Qué conviene hacer")
        for t in todo:
            o.line("  • " + t)
    else:
        o.ok("La parte local (SSSD y SSH) está lista para que un usuario cambie su contraseña caducada.")
    return True


def _sudo_file(group: str) -> Path:
    return Path(f"/etc/sudoers.d/90-opsdeck-ad-{re.sub(r'[^a-z0-9_-]+', '_', group.lower())}")


def _grant_sudo(ctx, group: str, dom: str) -> bool:
    if not GROUP_RE.match(group):
        ctx.out.error("Nombre de grupo no válido")
        return False
    ref = _ad_group_ref(group, dom)
    rule = f"# Gestionado por opsdeck ({system.operator()}, {time.strftime('%Y-%m-%d')})\n{ref} ALL=(ALL:ALL) ALL\n"
    with tempfile.NamedTemporaryFile("w", delete=False) as t:
        t.write(rule)
    try:
        if not system.run(["visudo", "-cf", t.name]).ok:
            ctx.out.error("La regla de sudo generada no es válida")
            return False
        f = _sudo_file(group)
        ok = apply(ctx, "dominio_sudo_grupo", group, ["install", "-o", "root", "-g", "root", "-m", "0440", t.name, str(f)],
                   f"regla={ref}")
        if ok and not system.run(["visudo", "-c"]).ok:
            f.unlink(missing_ok=True)
            ctx.out.error("sudoers dejó de validar; regla retirada")
            return False
        if ok:
            ctx.out.ok(f"Los miembros de '{group}' son administradores (sudo) de este equipo.")
        return ok
    finally:
        os.unlink(t.name)


def unir(ctx: Context, v: dict) -> bool:
    dom, admin = v["dominio"].strip().lower(), v["usuario"].strip()
    if not DOMAIN_RE.match(dom):
        ctx.out.error("Nombre de dominio no válido")
        return False
    if joined():
        ctx.out.error(f"El equipo ya está unido a {joined()['nombre']}. Sal antes del dominio.")
        return False
    if not comprobar(ctx, {"dominio": dom}):
        ctx.out.error("Corrige lo anterior y vuelve a intentarlo.")
        return False
    args = ["realm", "join", "--verbose", f"--user={admin}"]
    if v.get("ou"):
        args.append(f"--computer-ou={v['ou']}")
    args.append(dom)
    ctx.out.info(f"Uniendo a {dom} con la cuenta {admin}...")
    r = system.run(args, input=v["password"] + "\n", c_locale=True, timeout=300)
    if not r.ok:
        audit.record("unir_dominio", dom, f"ERROR_{r.rc}", f"cuenta={admin}")
        ctx.out.error("No se pudo unir al dominio:")
        for line in r.text.splitlines()[-12:]:
            ctx.out.line("    " + line)
        if "password" in r.text.lower() or "credentials" in r.text.lower():
            ctx.out.info("Revisa usuario y contraseña, y que la cuenta pueda añadir equipos al dominio.")
        return False
    audit.record("unir_dominio", dom, "OK", f"cuenta={admin} ou={v.get('ou') or '-'}")
    ctx.out.ok(f"Equipo unido a {dom}.")
    if v.get("home", True) and system.has_cmd("pam-auth-update"):
        apply(ctx, "dominio_mkhomedir", dom, ["pam-auth-update", "--enable", "mkhomedir"], quiet=True)
        ctx.out.ok("Se creará automáticamente la carpeta personal de cada usuario del dominio al entrar.")
    if v.get("cortos"):
        if _sssd_short_names(ctx, dom):
            ctx.out.ok("Los usuarios del dominio entran con su nombre corto (jperez en vez de jperez@dominio).")
    groups = [g.strip() for g in (v.get("permitidos") or "").split(",") if g.strip()]
    bad = [g for g in groups if not GROUP_RE.match(g) or g.startswith("-")]
    if bad:
        ctx.out.warn("Se ignoran nombres de grupo no válidos: " + ", ".join(bad))
        groups = [g for g in groups if g not in bad]
    if groups:
        apply(ctx, "dominio_denegar_todos", dom, ["realm", "deny", "--all"], quiet=True)
        for g in groups:
            if apply(ctx, "dominio_permitir_grupo", g, ["realm", "permit", "-g", g], quiet=True):
                ctx.out.ok(f"Pueden entrar los miembros de '{g}'.")
    else:
        ctx.out.warn("Pueden entrar TODOS los usuarios del dominio. Limítalo con 'Permitir acceso'.")
    if v.get("sudo"):
        _grant_sudo(ctx, v["sudo"].strip(), dom)
    ctx.out.info("Comprueba un usuario con 'Comprobar un usuario del dominio'.")
    return True


def permitir(ctx: Context, v: dict) -> bool:
    d = joined()
    if not d:
        ctx.out.error("El equipo no está unido a un dominio.")
        return False
    target, kind = v["nombre"].strip(), v["tipo"]
    if not GROUP_RE.match(target) or target.startswith("-"):
        ctx.out.error("Nombre no válido")
        return False
    if d.get("login-policy") == "allow-realm-logins":
        ctx.out.warn("Ahora puede entrar todo el dominio: se limitará a los permitidos explícitamente.")
        apply(ctx, "dominio_denegar_todos", d["nombre"], ["realm", "deny", "--all"], quiet=True)
    args = ["realm", "permit"] + (["-g"] if kind == "grupo" else []) + [target]
    ok = apply(ctx, "dominio_permitir", target, args, f"tipo={kind}", quiet=True)
    if ok:
        ctx.out.ok(f"Permitido: {target}. Se aplica en el próximo inicio de sesión.")
    return ok


def retirar(ctx: Context, v: dict) -> bool:
    d = joined()
    if not d:
        ctx.out.error("El equipo no está unido a un dominio.")
        return False
    target, kind = v["nombre"].strip(), v["tipo"]
    if not target or target.startswith("-") or re.search(r"[\x00-\x1f]", target):
        ctx.out.error("Nombre no válido")
        return False
    args = ["realm", "permit", "--withdraw"] + (["-g"] if kind == "grupo" else []) + [target]
    ok = apply(ctx, "dominio_retirar", target, args, f"tipo={kind}", quiet=True)
    if ok:
        ctx.out.ok(f"Retirado: {target}. Sus sesiones abiertas siguen hasta que las cierre.")
    return ok


def sudo_grupo(ctx: Context, v: dict) -> bool:
    d = joined()
    if not d:
        ctx.out.error("El equipo no está unido a un dominio.")
        return False
    return _grant_sudo(ctx, v["grupo"].strip(), d["nombre"])


def sudo_quitar(ctx: Context, v: dict) -> bool:
    f = _sudo_file(v["grupo"].strip())
    if not f.exists():
        ctx.out.info("Ese grupo no tiene sudo concedido por opsdeck.")
        return True
    ok = apply(ctx, "dominio_quitar_sudo_grupo", v["grupo"], ["rm", "-f", str(f)])
    if ok:
        ctx.out.ok(f"'{v['grupo']}' ya no tiene sudo en este equipo.")
    return ok


def probar(ctx: Context, v: dict) -> bool:
    name = v["usuario"].strip()
    r = system.run(["id", "--", name], c_locale=True, timeout=30)
    ctx.out.check(r.ok, f"id {name}: {r.text}")
    if not r.ok:
        d = joined()
        ctx.out.info("Si es un usuario del dominio, prueba con nombre@" + (d.get("nombre", "dominio")) +
                     " o revisa el estado de sssd en Servicios.")
        return False
    g = system.run(["getent", "passwd", "--", name], c_locale=True)
    if g.out.strip():
        f = g.out.strip().split(":")
        ctx.out.line(f"    home: {f[5]}  ·  shell: {f[6]}")
    return True


def salir(ctx: Context, v: dict) -> bool:
    d = joined()
    if not d:
        ctx.out.info("El equipo no está unido a ningún dominio.")
        return True
    args = ["realm", "leave", "--verbose", d["nombre"]]
    if v.get("usuario"):
        args.insert(2, f"--user={v['usuario']}")
    r = system.run(args, input=(v.get("password") or "") + "\n", c_locale=True, timeout=180)
    audit.record("salir_dominio", d["nombre"], "OK" if r.ok else f"ERROR_{r.rc}", f"cuenta={v.get('usuario') or '-'}")
    if not r.ok:
        ctx.out.error("No se pudo salir del dominio:")
        for line in r.text.splitlines()[-8:]:
            ctx.out.line("    " + line)
        return False
    for f in Path("/etc/sudoers.d").glob("90-opsdeck-ad-*"):
        f.unlink(missing_ok=True)
    ctx.out.ok(f"El equipo ha salido de {d['nombre']}. Los usuarios del dominio ya no pueden entrar.")
    return True


def _domain_guess() -> list[str]:
    d = joined()
    if d:
        return [d["nombre"]]
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith(("search", "domain")):
                return line.split()[1:]
    except OSError:
        pass
    return []


class Dominio(Module):
    id = "dominio"
    name = "Dominio (Active Directory)"
    category = "Sistemas"
    summary = "Unir el equipo a Active Directory y decidir quién entra y quién es administrador"
    requires = [cmd("realm", debian=["realmd", "sssd", "sssd-tools", "adcli", "libnss-sss", "libpam-sss",
                                     "samba-common-bin", "krb5-user"],
                    rhel=["realmd", "sssd", "adcli", "samba-common-tools", "krb5-workstation", "oddjob-mkhomedir"],
                    suse=["realmd", "sssd", "adcli", "samba-client", "krb5-client"], label="realmd y sssd")]
    help = """\
# Dominio (Active Directory)

Une este equipo Linux al dominio de Windows para que **los usuarios entren con su cuenta del
dominio** (la misma que en Windows), sin crear usuarios locales uno a uno.

> **Consultar y diagnosticar** (Estado, Revisar, Diagnosticar, Comprobar un usuario) está en las dos
> ediciones. **Aplicar cambios** (unir, ajustes, acceso, sudo, salir) es de la edición **completa**.

## Pasos
1. **Revisar dominio**: una sola revisión que vale para los dos casos y no cambia nada. Si el equipo ya
   está unido, repasa su salud (servicio, hora, claves, quién entra, sudo, acceso sin conexión) y qué
   conviene cambiar. Si aún no lo está, comprueba si está **listo para unirse**: DNS y controladores,
   hora sincronizada (Kerberos falla con más de 5 minutos de diferencia), herramientas instaladas y FQDN.
2. **Unir al dominio** (completa): necesitas una cuenta del dominio que pueda añadir equipos. La contraseña
   se usa una sola vez y no se guarda. Opciones:
   - **Unidad organizativa (OU)** donde crear el equipo, p. ej. `OU=Linux,OU=Servidores,DC=empresa,DC=local`.
   - **Grupos que pueden entrar**: si no indicas ninguno, puede entrar todo el dominio.
   - **Grupo administrador**: sus miembros tendrán sudo en este equipo.
   - **Nombres cortos**: entrar como `jperez` en lugar de `jperez@empresa.local`.
3. **Comprobar un usuario del dominio**: confirma que el equipo "ve" a ese usuario.

## Después: dejarlo seguro según cada caso
- **Revisar dominio**: repasa la unión y te dice qué conviene cambiar.
- **Diagnosticar contraseña caducada**: si un usuario del dominio no puede cambiar su contraseña caducada,
  revisa los dos puntos locales (SSSD `chpass_provider` y el SSH interactivo) y recuerda el tercero (la
  edad mínima de contraseña de la política del dominio, que se consulta en el módulo «LDAP»).
- **Ajustes de seguridad** (completa): cada implantación es distinta.
  - *Directivas de grupo*: si el AD ya decide por GPO quién entra en cada equipo, aplícalas;
    si no se usan, ponlas en "solo avisar" para que no bloqueen por sorpresa.
  - *Entrar sin conexión*: útil en portátiles; en servidores, mejor desactivarlo o limitar los días,
    para que una cuenta desactivada en el AD no siga entrando.
  - *Registro en DNS*: desactívalo si el DNS lo gestionáis a mano.
- *Permitir acceso* / *Retirar acceso* a usuarios o grupos del dominio.
- *Dar sudo a un grupo del dominio* / *Quitar sudo*.
- *Salir del dominio* deshace la unión y retira los sudo concedidos por opsdeck.

La gestión del propio Active Directory (crear usuarios, grupos, GPO) no se hace desde aquí:
este módulo configura **este equipo Linux** dentro del dominio.

Si un usuario del dominio no puede entrar: revisa *Estado* (quién está permitido), la hora, y el
servicio **sssd** en *Servicios*.
"""

    def actions(self):
        dom = Param("dominio", "Dominio", suggest=_domain_guess, help="Ej.: empresa.local")
        return [
            Action("estado", "Estado", estado, help="Si está unido, a qué dominio y quién puede entrar."),
            Action("revisar", "Revisar dominio", revisar, params=[
                Param("dominio", "Dominio (solo si el equipo aún NO está unido)", suggest=_domain_guess,
                      required=False, help="Déjalo vacío si ya está unido; se detecta solo.")],
                   help="Una sola revisión que vale para los dos casos: si el equipo está unido, repasa su salud "
                        "y qué conviene cambiar; si no lo está, comprueba si está listo para unirse (DNS, hora, "
                        "paquetes, FQDN). No cambia nada."),
            Action("diagnosticar", "Diagnosticar contraseña caducada", diagnosticar,
                   help="Por qué un usuario del dominio no puede cambiar su contraseña caducada: revisa SSSD y SSH."),
            Action("probar", "Comprobar un usuario del dominio", probar, params=[Param("usuario", "Usuario")]),
            Action("unir", "Unir al dominio", unir, changes=True, full=True, params=[
                dom,
                Param("usuario", "Cuenta del dominio con permiso para unir equipos", help="Ej.: administrador"),
                Param("password", "Contraseña de esa cuenta", "password", help="Se usa una vez y no se guarda."),
                Param("ou", "Unidad organizativa", required=False),
                Param("permitidos", "Grupos que pueden entrar (separados por coma, opcional)", required=False,
                      help="Vacío = todo el dominio. Ej.: IT, Administradores Linux"),
                Param("sudo", "Grupo del dominio que será administrador", required=False),
                Param("home", "Crear la carpeta personal al entrar", "bool", True, required=False),
                Param("cortos", "Entrar con nombre corto (sin @dominio)", "bool", True, required=False)],
                confirm="Se unirá este equipo al dominio {dominio} con la cuenta {usuario}. ¿Continuar?",
                help="Une el equipo al dominio y lo deja listo para que entren sus usuarios."),
            Action("ajustes", "Ajustes de seguridad", ajustes, changes=True, full=True, params=[
                Param("gpo", "Directivas de grupo (GPO) de inicio de sesión", "choice", "enforcing", choices=GPO_MODES,
                      help="Si el AD ya controla por GPO quién inicia sesión en cada equipo, déjalo en 'Aplicarlas'."),
                Param("offline", "Permitir entrar sin conexión con el dominio", "bool", True, required=False,
                      help="Portátiles: sí. Servidores siempre conectados: mejor no."),
                Param("dias_offline", "Máximo de días sin conexión (0 = sin límite)", "int", 7, required=False),
                Param("dns", "Registrar el equipo en el DNS del dominio", "bool", True, required=False)],
                help="Adapta la unión a cada implantación: no todos los dominios ni todos los equipos son iguales."),
            Action("permitir", "Permitir acceso", permitir, changes=True, full=True, params=[
                Param("nombre", "Usuario o grupo del dominio"),
                Param("tipo", "Es un", "choice", "grupo", choices=[("grupo", "Grupo"), ("usuario", "Usuario")])]),
            Action("retirar", "Retirar acceso", retirar, changes=True, full=True, params=[
                Param("nombre", "Usuario o grupo del dominio"),
                Param("tipo", "Es un", "choice", "grupo", choices=[("grupo", "Grupo"), ("usuario", "Usuario")])],
                confirm="Se retirará el acceso a {nombre}. ¿Continuar?"),
            Action("sudo", "Dar sudo a un grupo del dominio", sudo_grupo, changes=True, full=True,
                   params=[Param("grupo", "Grupo del dominio")],
                   confirm="Los miembros de '{grupo}' serán administradores de este equipo. ¿Continuar?"),
            Action("sudo_quitar", "Quitar sudo a un grupo del dominio", sudo_quitar, changes=True, full=True,
                   params=[Param("grupo", "Grupo del dominio")]),
            Action("salir", "Salir del dominio", salir, changes=True, full=True, params=[
                Param("usuario", "Cuenta del dominio (para borrar el equipo del AD)", required=False),
                Param("password", "Contraseña (si indicas cuenta)", "password", required=False)],
                confirm="El equipo saldrá del dominio y sus usuarios no podrán entrar. ¿Continuar?"),
        ]
