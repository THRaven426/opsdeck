"""LDAP / Active Directory (solo lectura): buscar usuarios, miembros de grupos, exportar y revisar
la higiene del directorio (cuentas inactivas, privilegiadas, contraseñas que no caducan, kerberoasting...).

La contraseña de la cuenta de consulta no se guarda: se pasa a ldapsearch en un fichero temporal
legible solo por root que se borra al terminar. Por defecto se usa LDAPS (cifrado)."""

from __future__ import annotations

import base64
import csv
import os
import re
import tempfile
import time
from typing import Optional

from ..core import audit, paths, results, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.config import settings

IN_CHAIN = "1.2.840.113556.1.4.1941"      # pertenencia recursiva a grupos
BIT_AND = "1.2.840.113556.1.4.803"
UAC = {"DESACTIVADA": 2, "SIN_PASSWORD_REQUERIDA": 32, "PASSWORD_NO_CADUCA": 65536,
       "DELEGACION_SIN_RESTRICCION": 524288, "SIN_PREAUTENTICACION_KERBEROS": 4194304}
ENABLED = f"(!(userAccountControl:{BIT_AND}:={UAC['DESACTIVADA']}))"
PERSON = "(&(objectCategory=person)(objectClass=user))"
USER_ATTRS = ["sAMAccountName", "displayName", "mail", "title", "department", "userAccountControl",
              "lastLogonTimestamp", "pwdLastSet", "whenCreated", "memberOf", "description"]


# ------------------------------------------------------------------ utilidades LDAP

def escape(value: str) -> str:
    """Escapa un valor para un filtro LDAP (RFC 4515)."""
    out = []
    for ch in value:
        if ch in '*()\\\x00':
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def base_from_domain(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.strip(".").split("."))


def parse_ldif(text: str) -> list[dict[str, list[str]]]:
    """Convierte la salida de ldapsearch -LLL en una lista de entradas {atributo: [valores]}."""
    entries, cur = [], None
    lines = text.splitlines()
    unfolded: list[str] = []
    for line in lines:                      # líneas plegadas (empiezan por espacio)
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    for line in unfolded:
        if not line.strip():
            cur = None
            continue
        if line.startswith("#"):
            continue
        m = re.match(r"^([^:]+)::\s?(.*)$", line)
        if m:
            k = m.group(1)
            try:
                v = base64.b64decode(m.group(2).strip()).decode("utf-8", "replace")
            except ValueError:
                v = m.group(2).strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            v = v.strip()
        else:
            continue
        if k == "dn":
            cur = {"dn": [v]}
            entries.append(cur)
        elif cur is not None:
            cur.setdefault(k, []).append(v)
    return entries


def filetime_to_date(v: str) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return "-"
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return "nunca"
    return time.strftime("%Y-%m-%d", time.gmtime(n / 1e7 - 11644473600))


def days_ago_filetime(days: int) -> int:
    return int((time.time() - days * 86400 + 11644473600) * 1e7)


def first(e: dict, k: str, default: str = "") -> str:
    return (e.get(k) or [default])[0]


def cn(dn: str) -> str:
    m = re.match(r"CN=((?:\\,|[^,])+)", dn, re.I)
    return m.group(1).replace("\\,", ",") if m else dn


class Conn:
    def __init__(self, v: dict):
        cfg = settings()
        self.server = (v.get("servidor") or cfg.get("ldap", "servidor", fallback="")).strip()
        self.base = (v.get("base") or cfg.get("ldap", "base", fallback="")).strip()
        self.user = (v.get("usuario") or cfg.get("ldap", "usuario", fallback="")).strip()
        self.password = v.get("password", "")
        self.mode = v.get("cifrado") or cfg.get("ldap", "cifrado", fallback="ldaps")
        if not self.base and "@" in self.user:
            self.base = base_from_domain(self.user.split("@", 1)[1])

    def problem(self) -> str:
        if not self.server:
            return "Falta el servidor (un controlador de dominio)"
        if not self.base:
            return "Falta la base de búsqueda (p. ej. DC=empresa,DC=local) o usa usuario@dominio"
        if not self.user or not self.password:
            return "Faltan la cuenta y la contraseña de consulta"
        return ""

    def search(self, flt: str, attrs: list[str], base: Optional[str] = None, scope: str = "sub") -> tuple[list[dict], str]:
        uri = f"ldaps://{self.server}" if self.mode == "ldaps" else f"ldap://{self.server}"
        fd, pwfile = tempfile.mkstemp(prefix="opsdeck-ldap-")
        try:
            os.write(fd, self.password.encode())
            os.close(fd)
            os.chmod(pwfile, 0o600)
            args = ["ldapsearch", "-LLL", "-x", "-H", uri, "-D", self.user, "-y", pwfile, "-b", base or self.base,
                    "-s", scope, "-o", "ldif-wrap=no", "-o", "nettimeout=15", "-E", "pr=500/noprompt", flt, *attrs]
            if self.mode == "starttls":
                args.insert(2, "-ZZ")
            env = {"LDAPTLS_REQCERT": "allow"} if settings().get("ldap", "verificar_certificado", fallback="no") == "no" else None
            r = system.run(args, timeout=120, env=env)
        finally:
            try:
                os.unlink(pwfile)
            except OSError:
                pass
        if r.rc not in (0, 4):     # 4 = sizelimit, devolvemos lo obtenido
            raw = (r.err or r.out).strip()
            return [], explain(raw) if raw else f"ldapsearch código {r.rc}"
        return parse_ldif(r.out), ""


AD_ERRORS = {"52e": "usuario o contraseña incorrectos", "525": "el usuario no existe",
             "530": "no puede iniciar sesión a esta hora", "531": "no puede iniciar sesión desde este equipo",
             "532": "la contraseña ha caducado", "533": "la cuenta está desactivada", "701": "la cuenta ha caducado",
             "773": "tiene que cambiar la contraseña", "775": "la cuenta está bloqueada por intentos fallidos"}


def explain(err: str) -> str:
    m = re.search(r"data ([0-9a-f]{3})", err)
    if m and m.group(1) in AD_ERRORS:
        return f"{AD_ERRORS[m.group(1)]} (código AD {m.group(1)})"
    if "Can't contact LDAP server" in err:
        return "no se puede conectar con el servidor (nombre, red, firewall o puerto 636/389)"
    if "Strong(er) authentication required" in err or "Transport encryption required" in err:
        return "el servidor exige cifrado: usa LDAPS o StartTLS"
    return err.strip()


def _conn(ctx, v) -> Optional[Conn]:
    c = Conn(v)
    p = c.problem()
    if p:
        ctx.out.error(p)
        return None
    return c


def _users_table(entries: list[dict]) -> list[list[str]]:
    rows = []
    for e in entries:
        uac = int(first(e, "userAccountControl", "0") or 0)
        rows.append([first(e, "sAMAccountName"), first(e, "displayName"), "no" if uac & 2 else "sí",
                     filetime_to_date(first(e, "lastLogonTimestamp")), filetime_to_date(first(e, "pwdLastSet")),
                     first(e, "department")])
    return sorted(rows, key=lambda r: r[0].lower())


USER_HEAD = ["Usuario", "Nombre", "Activa", "Último acceso*", "Contraseña cambiada", "Departamento"]


# ------------------------------------------------------------------ acciones

def probar(ctx: Context, v: dict) -> bool:
    c = _conn(ctx, v)
    if not c:
        return False
    res, err = c.search("(objectClass=domain)", ["dc", "msDS-Behavior-Version", "lockoutThreshold", "minPwdLength",
                                                 "maxPwdAge"], scope="base")
    if err:
        ctx.out.error(f"No se pudo conectar: {explain(err)}")
        ctx.out.info("Comprueba servidor, cuenta (usuario@dominio) y contraseña. Si falla LDAPS, prueba 'starttls'.")
        audit.record("ldap_probar", c.server, "ERROR", c.user)
        return False
    ctx.out.ok(f"Conectado a {c.server} como {c.user} ({c.mode}).")
    if res:
        e = res[0]
        age = first(e, "maxPwdAge")
        days = abs(int(age)) // 864000000000 if age.lstrip("-").isdigit() and int(age) else 0
        ctx.out.table(["Política del dominio", "Valor"], [
            ["Longitud mínima de contraseña", first(e, "minPwdLength", "?")],
            ["Caducidad de contraseña (días)", str(days) if days else "no caduca"],
            ["Bloqueo tras N intentos", first(e, "lockoutThreshold", "?") + (" (sin bloqueo)" if first(e, "lockoutThreshold") == "0" else "")]])
    audit.record("ldap_probar", c.server, "OK", c.user)
    return True


def buscar(ctx: Context, v: dict) -> bool:
    c = _conn(ctx, v)
    if not c:
        return False
    t = escape(v["texto"].strip())
    flt = f"(&{PERSON}(|(sAMAccountName=*{t}*)(displayName=*{t}*)(mail=*{t}*)))"
    res, err = c.search(flt, USER_ATTRS)
    if err:
        ctx.out.error(err)
        return False
    if not res:
        ctx.out.info("Sin resultados.")
        return True
    ctx.out.table(USER_HEAD, _users_table(res)[:100])
    if len(res) == 1:
        e = res[0]
        ctx.out.title(f"Grupos de {first(e, 'sAMAccountName')}")
        ctx.out.line("  " + ", ".join(sorted(cn(g) for g in e.get("memberOf", []))) or "  (ninguno directo)")
    ctx.out.info("* Último acceso aproximado (lastLogonTimestamp se replica con hasta 14 días de retraso).")
    return True


def miembros(ctx: Context, v: dict) -> bool:
    c = _conn(ctx, v)
    if not c:
        return False
    g, err = c.search(f"(&(objectClass=group)(|(cn={escape(v['grupo'])})(sAMAccountName={escape(v['grupo'])})))", ["dn"])
    if err or not g:
        ctx.out.error(err or f"No existe el grupo '{v['grupo']}'")
        return False
    dn = first(g[0], "dn")
    res, err = c.search(f"(&{PERSON}(memberOf:{IN_CHAIN}:={escape(dn)}))", USER_ATTRS)
    if err:
        ctx.out.error(err)
        return False
    ctx.out.title(f"{len(res)} usuarios en '{cn(dn)}' (incluidos los de grupos anidados)")
    ctx.out.table(USER_HEAD, _users_table(res))
    return True


def exportar(ctx: Context, v: dict) -> bool:
    c = _conn(ctx, v)
    if not c:
        return False
    res, err = c.search(PERSON, USER_ATTRS)
    if err:
        ctx.out.error(err)
        return False
    paths.ensure_private_dir(paths.DATA_DIR, 0o750)
    paths.ensure_private_dir(paths.REPORT_DIR, 0o750)
    dest = paths.REPORT_DIR / f"usuarios_ad_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    with open(dest, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["usuario", "nombre", "correo", "puesto", "departamento", "activa", "ultimo_acceso",
                    "password_cambiada", "creada", "grupos"])
        for e in res:
            uac = int(first(e, "userAccountControl", "0") or 0)
            w.writerow([first(e, "sAMAccountName"), first(e, "displayName"), first(e, "mail"), first(e, "title"),
                        first(e, "department"), "no" if uac & 2 else "si", filetime_to_date(first(e, "lastLogonTimestamp")),
                        filetime_to_date(first(e, "pwdLastSet")), first(e, "whenCreated")[:8],
                        ",".join(cn(g) for g in e.get("memberOf", []))])
    os.chmod(dest, 0o640)
    audit.record("ldap_exportar_usuarios", c.server, "OK", f"{len(res)} usuarios -> {dest}")
    ctx.out.ok(f"{len(res)} usuarios exportados a {dest}")
    return True


def revision(ctx: Context, v: dict) -> bool:
    c = _conn(ctx, v)
    if not c:
        return False
    days = int(v.get("dias") or 90)
    old = days_ago_filetime(days)
    year = days_ago_filetime(365)
    report: list[str] = [f"Revisión de Active Directory · {c.base} · {time.strftime('%Y-%m-%d %H:%M')} · {system.operator()}"]
    counts = {"ALTO": 0, "MEDIO": 0, "BAJO": 0}

    def finding(level: str, title: str, entries: list[dict], why: str, show=lambda e: first(e, "sAMAccountName")):
        if not entries:
            ctx.out.check(True, f"{title}: ninguno")
            report.append(f"[OK] {title}: ninguno")
            return
        counts[level] += 1
        names = sorted(show(e) for e in entries)
        ctx.out.check(False, f"[{level}] {title}: {len(entries)}")
        ctx.out.line("        " + why)
        ctx.out.line("        " + ", ".join(names[:25]) + (f" ... (+{len(names) - 25})" if len(names) > 25 else ""))
        report.append(f"[{level}] {title}: {len(entries)}\n    {why}\n    " + ", ".join(names))

    def q(flt, attrs=("sAMAccountName",)):
        res, err = c.search(flt, list(attrs))
        if err:
            ctx.out.error(err)
            raise RuntimeError(err)
        return res

    try:
        ctx.out.title("Cuentas privilegiadas")
        for grp in ("Domain Admins", "Enterprise Admins", "Administrators", "Admins. del dominio",
                    "Administradores de empresas", "Administradores"):
            gq = q(f"(&(objectClass=group)(cn={escape(grp)}))", ["dn"])
            if gq:
                mem = q(f"(&{PERSON}(memberOf:{IN_CHAIN}:={escape(first(gq[0], 'dn'))}))", ["sAMAccountName", "pwdLastSet"])
                ctx.out.line(f"  {grp}: {len(mem)} → " + ", ".join(sorted(first(e, 'sAMAccountName') for e in mem)))
                report.append(f"{grp}: " + ", ".join(sorted(first(e, 'sAMAccountName') for e in mem)))
        priv_old = q(f"(&{PERSON}{ENABLED}(adminCount=1)(pwdLastSet<={year}))", ["sAMAccountName"])
        finding("ALTO", "Cuentas privilegiadas con contraseña de más de 1 año", priv_old,
                "Las cuentas de administración deberían cambiar la contraseña con más frecuencia.")

        ctx.out.title("Riesgos de autenticación")
        finding("ALTO", "Sin preautenticación Kerberos (AS-REP roasting)",
                q(f"(&{PERSON}{ENABLED}(userAccountControl:{BIT_AND}:={UAC['SIN_PREAUTENTICACION_KERBEROS']}))"),
                "Permiten obtener un hash crackeable sin credenciales. Activa la preautenticación.")
        finding("MEDIO", "Usuarios con SPN (kerberoasting)",
                q(f"(&{PERSON}{ENABLED}(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"),
                "Su contraseña puede atacarse offline. Usa contraseñas largas o cuentas gMSA.")
        finding("MEDIO", "Contraseña no requerida (PASSWD_NOTREQD)",
                q(f"(&{PERSON}{ENABLED}(userAccountControl:{BIT_AND}:={UAC['SIN_PASSWORD_REQUERIDA']}))"),
                "Pueden tener la contraseña vacía.")
        finding("MEDIO", "Equipos con delegación sin restricciones (no DC)",
                q(f"(&(objectCategory=computer)(userAccountControl:{BIT_AND}:={UAC['DELEGACION_SIN_RESTRICCION']})"
                  f"(!(primaryGroupID=516)))"), "Permiten suplantar a cualquier usuario que se conecte a ellos.")

        ctx.out.title("Higiene de cuentas")
        finding("MEDIO", "La contraseña nunca caduca",
                q(f"(&{PERSON}{ENABLED}(userAccountControl:{BIT_AND}:={UAC['PASSWORD_NO_CADUCA']}))"),
                "Revisa si son cuentas de servicio justificadas.")
        finding("MEDIO", f"Activas sin acceso en {days} días",
                q(f"(&{PERSON}{ENABLED}(lastLogonTimestamp<={old}))"),
                "Cuentas que nadie usa: desactívalas si no hacen falta.")
        finding("BAJO", "Activas que nunca han iniciado sesión",
                q(f"(&{PERSON}{ENABLED}(!(lastLogonTimestamp=*))(whenCreated<={time.strftime('%Y%m%d', time.gmtime(time.time() - 30 * 86400))}000000.0Z))"),
                "Creadas hace más de 30 días y nunca usadas.")
        finding("BAJO", "Cuentas desactivadas que siguen en grupos privilegiados",
                q(f"(&{PERSON}(adminCount=1)(userAccountControl:{BIT_AND}:={UAC['DESACTIVADA']})(!(sAMAccountName=krbtgt)))"),
                "Límpialas de los grupos de administración.")

        ctx.out.title("Equipos")
        obsolete = q("(&(objectCategory=computer)(|(operatingSystem=*2003*)(operatingSystem=*2008*)"
                     "(operatingSystem=*2012*)(operatingSystem=*XP*)(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)))",
                     ["cn", "operatingSystem"])
        finding("ALTO", "Equipos con sistema operativo sin soporte", obsolete,
                "Sin parches de seguridad: aíslalos o actualízalos.",
                show=lambda e: f"{first(e, 'cn')} ({first(e, 'operatingSystem')})")
        finding("BAJO", f"Equipos sin contactar con el dominio en {days} días",
                q(f"(&(objectCategory=computer)(lastLogonTimestamp<={old}))", ["cn"]),
                "Probablemente retirados: desactívalos o bórralos del AD.", show=lambda e: first(e, "cn"))
    except RuntimeError:
        return False

    summary = f"Resumen: ALTO={counts['ALTO']} MEDIO={counts['MEDIO']} BAJO={counts['BAJO']}"
    ctx.out.title(summary)
    report.append(summary)
    d = results.new_dir("ldap", "revision_ad")
    results.write(d / "revision.txt", "\n".join(report) + "\n")
    audit.record("ldap_revision", c.base, "OK", summary)
    ctx.out.info(f"Informe guardado en {d / 'revision.txt'}")
    return True


def guardar(ctx: Context, v: dict) -> bool:
    from ..core.config import save
    cfg = settings()
    if not cfg.has_section("ldap"):
        cfg.add_section("ldap")
    for k in ("servidor", "base", "usuario", "cifrado"):
        if v.get(k):
            cfg.set("ldap", k, v[k])
    save()
    ctx.out.ok("Conexión guardada (sin contraseña). Se propondrá por defecto en las demás acciones.")
    return True


def _default(key: str, fallback: str = ""):
    return lambda: settings().get("ldap", key, fallback=fallback)


def _dc_guess() -> list[str]:
    out = []
    if system.has_cmd("realm"):
        for line in system.run(["realm", "list"], c_locale=True).out.splitlines():
            if line and not line.startswith(" "):
                out.append(line.strip())
    return out


class Ldap(Module):
    id = "ldap"
    name = "LDAP / Active Directory"
    category = "Sistemas"
    summary = "Buscar usuarios y grupos del directorio y revisar su higiene (solo lectura)"
    requires = [cmd("ldapsearch", debian="ldap-utils", rhel="openldap-clients", suse="openldap2-client",
                    arch="openldap", label="ldapsearch")]
    help = """\
# LDAP / Active Directory

Consulta el directorio **sin cambiar nada**: solo lectura. Para administrar el AD (altas, grupos,
GPO) usa las herramientas de Windows; aquí se consulta y se revisa.

Necesitas una **cuenta del dominio para consultar** (cualquier usuario normal sirve; mejor una
cuenta dedicada) y el nombre o IP de un **controlador de dominio**. Usa *Guardar conexión* para no
repetir los datos: se guardan servidor, base y cuenta, **nunca la contraseña**.

- **Probar conexión**: comprueba los datos y muestra la política de contraseñas del dominio.
- **Buscar usuarios**: por nombre de usuario, nombre completo o correo. Si hay uno solo, muestra sus grupos.
- **Miembros de un grupo**: incluye los que están dentro de grupos anidados.
- **Exportar usuarios (CSV)**: todo el directorio en una hoja de cálculo.
- **Revisión del Active Directory**: los problemas de seguridad más habituales:
  - quién es administrador del dominio y si sus contraseñas son antiguas;
  - cuentas sin preautenticación Kerberos (AS-REP roasting) y con SPN (kerberoasting);
  - contraseñas que no caducan o no requeridas; cuentas y equipos inactivos;
  - equipos con sistemas sin soporte y con delegación sin restricciones.

**Cifrado**: *ldaps* (puerto 636) por defecto. Si el controlador no tiene certificado, prueba *starttls*.
*sin cifrar* envía la contraseña en claro por la red: evítalo.
"""

    def actions(self):
        conn = [
            Param("servidor", "Controlador de dominio", default=_default("servidor")(), suggest=_dc_guess,
                  help="Nombre o IP de un controlador de dominio"),
            Param("usuario", "Cuenta de consulta (usuario@dominio)", default=_default("usuario")()),
            Param("password", "Contraseña", "password", help="No se guarda."),
            Param("base", "Base de búsqueda", default=_default("base")(), required=False,
                  help="Se deduce de usuario@dominio. Ej.: DC=empresa,DC=local"),
            Param("cifrado", "Cifrado", "choice", _default("cifrado", "ldaps")(), choices=[
                ("ldaps", "LDAPS (recomendado)"), ("starttls", "StartTLS"), ("plano", "Sin cifrar (no recomendado)")]),
        ]
        return [
            Action("probar", "Probar conexión", probar, params=conn),
            Action("buscar", "Buscar usuarios", buscar, params=[Param("texto", "Buscar"), *conn]),
            Action("miembros", "Miembros de un grupo", miembros, params=[Param("grupo", "Grupo"), *conn]),
            Action("exportar", "Exportar usuarios (CSV)", exportar, params=conn),
            Action("revision", "Revisión del Active Directory", revision, params=[
                Param("dias", "Días sin uso para considerar inactiva", "int", 90, required=False), *conn],
                help="Busca los problemas de seguridad más comunes del dominio y guarda un informe."),
            Action("guardar", "Guardar conexión", guardar, changes=True, params=[p for p in conn if p.name != "password"],
                   help="Guarda servidor, cuenta, base y cifrado para no repetirlos. Nunca la contraseña."),
        ]
