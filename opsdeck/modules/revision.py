"""Revisión de seguridad del equipo, sin herramientas externas.

Cada hallazgo tiene un nivel (ALTO/MEDIO/BAJO), un identificador estable y una recomendación.
Se guarda cada revisión y se compara con la anterior: qué es nuevo y qué se ha resuelto."""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from pathlib import Path

from ..core import accounts as acc
from ..core import audit, packages, results, system
from ..core.catalog import Action, Context, Module

LEVELS = ("ALTO", "MEDIO", "BAJO")


class Findings:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, level: str, fid: str, area: str, text: str, fix: str = "") -> None:
        self.items.append({"nivel": level, "id": fid, "area": area, "texto": text, "solucion": fix})


# ------------------------------------------------------------------ comprobaciones

def check_accounts(f: Findings) -> None:
    passwd = [l.split(":") for l in Path("/etc/passwd").read_text().splitlines() if l.count(":") >= 6]
    for p in passwd:
        if p[2] == "0" and p[0] != "root":
            f.add("ALTO", f"uid0:{p[0]}", "Cuentas", f"'{p[0]}' tiene UID 0 (equivale a root)",
                  "Si no es intencionado, elimínala o cambia su UID.")
    for name in [l.split(":")[0] for l in Path("/etc/shadow").read_text().splitlines() if l.split(":")[1:2] == [""]]:
        f.add("ALTO", f"sinclave:{name}", "Cuentas", f"'{name}' entra SIN contraseña",
              "Usuarios › Restablecer contraseña, o Bloquear.")
    for kind, col in (("nombre", 0), ("UID", 2)):
        for v, n in Counter(p[col] for p in passwd).items():
            if n > 1:
                f.add("ALTO", f"dup{kind}:{v}", "Cuentas", f"{kind} duplicado: {v}", "Revisa /etc/passwd.")
    for name in acc.human_names() + ["root"]:
        s = acc.sudo_summary(name)
        if s == "si (NOPASSWD)":
            f.add("MEDIO", f"nopasswd:{name}", "Cuentas", f"'{name}' usa sudo SIN contraseña",
                  "Quita NOPASSWD salvo que sea imprescindible (Usuarios › Quitar sudo / Dar sudo con regla).")
    for g in acc.priv_groups():
        grp = acc.group(g)
        if grp and grp.gr_mem and g in ("docker", "lxd", "disk", "kali-trusted", "shadow"):
            f.add("MEDIO", f"grupo:{g}", "Cuentas", f"Miembros de '{g}' (equivale a root): {', '.join(grp.gr_mem)}",
                  "Deja ahí solo a administradores.")
    no_expiry = [n for n in acc.human_names() if acc.has_real_password(n) and
                 (acc.shadow(n) or [""] * 9)[4] in ("", "99999")]
    if no_expiry:
        f.add("BAJO", "sincaducidad", "Cuentas", f"Contraseñas que no caducan: {', '.join(no_expiry)}",
              "Usuarios › Política de caducidad.")
    for u in acc.local_users():
        if not acc.is_human(u.pw_uid):
            continue
        home = Path(u.pw_dir)
        if home.is_dir():
            st = home.stat()
            if st.st_uid != u.pw_uid:
                f.add("ALTO", f"homeowner:{u.pw_name}", "Cuentas", f"El home de '{u.pw_name}' pertenece a otro usuario",
                      f"chown {u.pw_name} {home}")
            elif st.st_mode & 0o007:
                f.add("MEDIO", f"homeperm:{u.pw_name}", "Cuentas",
                      f"El home de '{u.pw_name}' es accesible por todos (permisos {oct(st.st_mode)[-3:]})",
                      f"chmod 750 {home}")
        ak = home / ".ssh" / "authorized_keys"
        if ak.is_symlink():
            f.add("ALTO", f"aksymlink:{u.pw_name}", "Cuentas", f"authorized_keys de '{u.pw_name}' es un enlace simbólico",
                  "Revísalo a mano: puede ser un intento de escalada.")
        elif ak.exists() and ak.stat().st_mode & 0o022:
            f.add("MEDIO", f"akperm:{u.pw_name}", "Cuentas", f"authorized_keys de '{u.pw_name}' es escribible por otros",
                  f"chmod 600 {ak}")


def check_files(f: Findings) -> None:
    for p, bad in (("/etc/shadow", 0o004), ("/etc/gshadow", 0o004), ("/etc/passwd", 0o022), ("/etc/group", 0o022),
                   ("/etc/sudoers", 0o022)):
        if os.path.exists(p) and os.stat(p).st_mode & bad:
            f.add("ALTO", f"perm:{p}", "Ficheros", f"{p} tiene permisos demasiado abiertos ({oct(os.stat(p).st_mode)[-3:]})",
                  f"Restaura los permisos por defecto de {p}.")
    for p in Path("/etc/sudoers.d").glob("*"):
        st = p.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            f.add("MEDIO", f"sudoersd:{p.name}", "Ficheros", f"{p} debería ser de root y no escribible por otros",
                  f"chown root:root {p} && chmod 440 {p}")
    if Path("/etc/ld.so.preload").exists() and Path("/etc/ld.so.preload").read_text().strip():
        f.add("ALTO", "ldpreload", "Ficheros", "/etc/ld.so.preload carga librerías en todos los programas",
              "Es una técnica habitual de rootkits: revisa su contenido (Triaje › Persistencia).")
    r = system.run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], timeout=60)
    ww = [l for l in r.out.splitlines() if l.strip()]
    if ww:
        f.add("ALTO", "etcworld", "Ficheros", f"{len(ww)} ficheros de /etc escribibles por cualquiera: " + ", ".join(ww[:5]),
              "chmod o-w sobre ellos.")


def sshd_effective() -> dict:
    sshd = system.which("sshd")
    if not system.has_cmd("sshd"):
        return {}
    r = system.run([sshd, "-T"], c_locale=True)
    if not r.ok:
        r = system.run([sshd, "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"], c_locale=True)
    return {l.split(None, 1)[0].lower(): (l.split(None, 1) + [""])[1] for l in r.out.splitlines() if l.strip()}


def check_ssh(f: Findings) -> None:
    c = sshd_effective()
    if not c:
        return
    if c.get("permitrootlogin") in ("yes",):
        f.add("ALTO", "ssh:root", "SSH", "SSH permite entrar como root con contraseña",
              "PermitRootLogin no (o prohibit-password) en /etc/ssh/sshd_config.")
    if c.get("permitemptypasswords") == "yes":
        f.add("ALTO", "ssh:empty", "SSH", "SSH permite contraseñas vacías", "PermitEmptyPasswords no")
    if c.get("passwordauthentication") == "yes":
        f.add("BAJO", "ssh:password", "SSH", "SSH acepta contraseñas (no solo claves)",
              "Si todos usan claves: PasswordAuthentication no. Si no, limita el acceso por firewall a la red de administración.")
    if c.get("x11forwarding") == "yes":
        f.add("BAJO", "ssh:x11", "SSH", "SSH permite reenvío X11", "X11Forwarding no, si no se usa.")
    try:
        if int(c.get("maxauthtries", "6")) > 4:
            f.add("BAJO", "ssh:maxauth", "SSH", f"MaxAuthTries {c.get('maxauthtries')} (intentos por conexión)",
                  "MaxAuthTries 3 o 4.")
    except ValueError:
        pass


def check_network(f: Findings) -> None:
    fw = ""
    if system.has_cmd("ufw"):
        fw = "ufw" if "Status: active" in system.run(["ufw", "status"], c_locale=True).out else ""
    if not fw and system.has_cmd("firewall-cmd"):
        fw = "firewalld" if system.run(["firewall-cmd", "--state"], c_locale=True).out.strip() == "running" else ""
    if not fw and system.has_cmd("nft"):
        rules = system.run(["nft", "list", "ruleset"], c_locale=True).out
        fw = "nftables" if re.search(r"\b(drop|reject)\b", rules) else ""
    listening = []
    if system.has_cmd("ss"):
        for line in system.run(["ss", "-ltnH"], c_locale=True).out.splitlines():
            parts = line.split()
            if len(parts) > 3 and not parts[3].startswith(("127.", "[::1]", "::1")):
                listening.append(parts[3].rpartition(":")[2])
    if not fw:
        f.add("MEDIO" if listening else "BAJO", "firewall:off", "Red",
              f"Sin firewall activo; puertos accesibles desde la red: {', '.join(sorted(set(listening), key=lambda x: int(x) if x.isdigit() else 0)) or 'ninguno'}",
              "Firewall › Activar firewall.")
    for key, want, level, text in (
            ("kernel.randomize_va_space", "2", "MEDIO", "ASLR no está al máximo"),
            ("fs.protected_symlinks", "1", "BAJO", "Protección de enlaces simbólicos desactivada"),
            ("net.ipv4.conf.all.accept_redirects", "0", "BAJO", "Se aceptan redirecciones ICMP"),
            ("kernel.kptr_restrict", "1", "BAJO", "Las direcciones del kernel son visibles"),
    ):
        p = Path("/proc/sys") / key.replace(".", "/")
        try:
            val = p.read_text().strip()
        except OSError:
            continue
        ok = val == want or (key == "kernel.kptr_restrict" and val in ("1", "2"))
        if not ok:
            f.add(level, f"sysctl:{key}", "Kernel", f"{text} ({key} = {val})", f"sysctl -w {key}={want} y en /etc/sysctl.d/")


def check_updates(f: Findings) -> None:
    pm = packages.manager()
    if pm.name != "apt":
        return
    r = system.run(["apt", "list", "--upgradable"], c_locale=True, timeout=60)
    lines = [l for l in r.out.splitlines() if "upgradable" in l]
    sec = [l.split("/")[0] for l in lines if "-security" in l]
    if sec:
        f.add("ALTO", "updates:security", "Actualizaciones", f"{len(sec)} actualizaciones de seguridad pendientes",
              "Sistema › Instalar actualizaciones.")
    elif len(lines) > 20:
        f.add("BAJO", "updates:many", "Actualizaciones", f"{len(lines)} actualizaciones pendientes",
              "Sistema › Instalar actualizaciones.")
    if not pm.is_installed("unattended-upgrades"):
        f.add("BAJO", "updates:auto", "Actualizaciones", "No hay actualizaciones automáticas de seguridad",
              "apt install unattended-upgrades")
    if os.path.exists("/var/run/reboot-required"):
        f.add("MEDIO", "updates:reboot", "Actualizaciones", "Hay actualizaciones que solo se aplican tras reiniciar",
              "Programa un reinicio.")


def check_services(f: Findings) -> None:
    sesman = Path("/etc/xrdp/sesman.ini")
    if sesman.exists() and re.search(r"^\s*AllowRootLogin\s*=\s*(true|yes|1)", sesman.read_text(errors="replace"), re.M | re.I):
        f.add("MEDIO", "xrdp:root", "Servicios", "El escritorio remoto (xrdp) permite entrar como root",
              "AllowRootLogin=false en /etc/xrdp/sesman.ini y reiniciar xrdp-sesman desde SSH.")
    if system.has_cmd("timedatectl"):
        r = system.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], c_locale=True)
        if r.ok and r.out.strip() == "no":
            f.add("BAJO", "time", "Servicios", "La hora no está sincronizada (afecta a Kerberos y a los registros)",
                  "Activa NTP: timedatectl set-ntp true")
    if system.systemd_available():
        failed = [l.split()[0] for l in system.run(["systemctl", "--failed", "--no-legend", "--plain"],
                                                  c_locale=True).out.splitlines() if l.strip()]
        if failed:
            f.add("BAJO", "systemd:failed", "Servicios", f"Servicios con fallos: {', '.join(failed)}", "Servicios › Estado.")


CHECKS = [("Cuentas", check_accounts), ("Ficheros", check_files), ("SSH", check_ssh), ("Red", check_network),
          ("Kernel", None), ("Actualizaciones", check_updates), ("Servicios", check_services)]


def run_review() -> Findings:
    f = Findings()
    for _, fn in CHECKS:
        if fn is None:
            continue
        try:
            fn(f)
        except Exception as e:  # una comprobación rota no debe impedir el resto
            f.add("BAJO", f"error:{fn.__name__}", "Revisión", f"No se pudo completar {fn.__name__}: {e}")
    return f


def previous() -> tuple[str, list[dict]]:
    for d in results.sessions("revision")[1:]:
        p = d / "hallazgos.json"
        if p.exists():
            try:
                return d.name, json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
    return "", []


def revisar(ctx: Context, v: dict) -> bool:
    ctx.out.info("Revisando el equipo...")
    f = run_review()
    d = results.new_dir("revision", system.hostname())
    results.write(d / "hallazgos.json", json.dumps(f.items, ensure_ascii=False, indent=1))
    counts = Counter(i["nivel"] for i in f.items)
    for area in dict.fromkeys(i["area"] for i in f.items):
        ctx.out.title(area)
        for i in [x for x in f.items if x["area"] == area]:
            ctx.out.check(False, f"[{i['nivel']}] {i['texto']}")
            if i["solucion"]:
                ctx.out.line(f"        → {i['solucion']}")
    clean = [a for a, _ in CHECKS if a not in {i["area"] for i in f.items}]
    if clean:
        ctx.out.title("Sin hallazgos")
        ctx.out.line("  " + ", ".join(clean))
    when, prev = previous()
    if prev:
        before, now = {i["id"] for i in prev}, {i["id"] for i in f.items}
        new, fixed = [i for i in f.items if i["id"] not in before], [i for i in prev if i["id"] not in now]
        ctx.out.title(f"Comparado con la revisión anterior ({when[:8]} {when[9:11]}:{when[11:13]})")
        ctx.out.line(f"  Nuevos: {len(new)}   Resueltos: {len(fixed)}")
        for i in new:
            ctx.out.line(f"  + [{i['nivel']}] {i['texto']}")
        for i in fixed:
            ctx.out.line(f"  ✓ resuelto: {i['texto']}")
    summary = " ".join(f"{lv}={counts.get(lv, 0)}" for lv in LEVELS)
    ctx.out.title(f"Resumen: {summary}")
    text = [f"Revisión de seguridad · {system.hostname()} · {time.strftime('%Y-%m-%d %H:%M')} · {system.operator()}", ""]
    text += [f"[{i['nivel']}] {i['area']}: {i['texto']}\n    → {i['solucion']}" for i in f.items]
    text += ["", f"Resumen: {summary}"]
    results.write(d / "informe.txt", "\n".join(text) + "\n")
    audit.record("revision_seguridad", system.hostname(), "OK", summary)
    ctx.out.info(f"Informe: {d / 'informe.txt'}")
    return True


def historial(ctx: Context, v: dict) -> bool:
    rows = []
    for d in results.sessions("revision", 20):
        p = d / "hallazgos.json"
        if not p.exists():
            continue
        items = json.loads(p.read_text())
        c = Counter(i["nivel"] for i in items)
        rows.append([f"{d.name[:4]}-{d.name[4:6]}-{d.name[6:8]} {d.name[9:11]}:{d.name[11:13]}",
                     str(c.get("ALTO", 0)), str(c.get("MEDIO", 0)), str(c.get("BAJO", 0))])
    if not rows:
        ctx.out.info("Aún no hay revisiones guardadas.")
        return True
    ctx.out.table(["Fecha", "ALTO", "MEDIO", "BAJO"], rows)
    return True


class Revision(Module):
    id = "revision"
    name = "Revisión de seguridad"
    category = "Blue team"
    summary = "Comprueba cuentas, permisos, SSH, firewall, kernel y actualizaciones; compara con la anterior"
    help = """\
# Revisión de seguridad

Revisa los puntos débiles más habituales **sin instalar nada** y te dice cómo corregir cada uno.

| Área | Qué mira |
|---|---|
| Cuentas | UID 0 extra, cuentas sin contraseña, duplicados, sudo sin contraseña, grupos que equivalen a root, contraseñas que no caducan, permisos de homes y claves SSH |
| Ficheros | permisos de passwd/shadow/sudoers, /etc/ld.so.preload, ficheros de /etc escribibles por todos |
| SSH | root con contraseña, contraseñas vacías, X11, intentos por conexión |
| Red y kernel | firewall activo y puertos expuestos, ASLR y otros parámetros del kernel |
| Actualizaciones | parches de seguridad pendientes, actualizaciones automáticas, reinicio pendiente |
| Servicios | xrdp con root, hora sincronizada, servicios con fallos |

Cada revisión se guarda y se **compara con la anterior**: verás qué problemas son **nuevos** y cuáles
has **resuelto**. *Historial* muestra la evolución.

Para una auditoría más profunda (cientos de comprobaciones) usa el módulo **Bastionado (Lynis)**.
"""

    def actions(self):
        return [
            Action("revisar", "Revisar el equipo", revisar,
                   help="Ejecuta todas las comprobaciones, guarda el informe y lo compara con la revisión anterior."),
            Action("historial", "Historial de revisiones", historial),
        ]
