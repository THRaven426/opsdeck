"""Triaje ante incidentes: persistencia, procesos sospechosos, ficheros recientes y recogida de evidencias.

Solo lee: no borra ni para nada. La recogida sigue el orden de volatilidad (primero procesos y
conexiones, después configuración y registros) y genera un manifiesto con SHA-256 de cada fichero."""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import time
from pathlib import Path

from ..core import accounts as acc
from ..core import audit, results, system
from ..core.catalog import Action, Context, Module, Param

SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def _recent(p: Path, days: int) -> bool:
    try:
        return time.time() - p.lstat().st_mtime < days * 86400
    except OSError:
        return False


def _when(p: Path) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(p.lstat().st_mtime))
    except OSError:
        return "?"


def _owner_pkg(path: str) -> str:
    """Paquete al que pertenece el fichero ('' si no es de ningún paquete)."""
    if system.has_cmd("dpkg-query"):
        # con /usr fusionado dpkg puede tener registrado /bin/x en lugar de /usr/bin/x (y al revés)
        alt = path[4:] if path.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/")) else \
            "/usr" + path if path.startswith(("/bin/", "/sbin/", "/lib/")) else ""
        for candidate in filter(None, (path, alt)):
            r = system.run(["dpkg-query", "-S", candidate], c_locale=True)
            if r.ok:
                return r.out.split(":", 1)[0]
        return ""
    if system.has_cmd("rpm"):
        r = system.run(["rpm", "-qf", path], c_locale=True)
        return r.out.strip() if r.ok and "not owned" not in r.out else ""
    return "?"


def homes() -> list[Path]:
    out = [Path("/root")]
    for u in acc.local_users():
        if acc.is_human(u.pw_uid):
            out.append(Path(u.pw_dir))
    return [h for h in out if h.is_dir()]


def persistence(days: int) -> list[list[str]]:
    """Filas: [mecanismo, ruta, detalle, modificado, marca]. marca = '!' si es reciente o sospechoso."""
    rows: list[list[str]] = []

    def add(kind: str, p: Path, detail: str = "", flag: bool = False) -> None:
        rows.append([kind, str(p), detail[:90], _when(p), "!" if flag or _recent(p, days) else ""])

    # cron
    for p in [Path("/etc/crontab"), *Path("/etc/cron.d").glob("*"), *Path("/var/spool/cron/crontabs").glob("*"),
              *Path("/var/spool/cron").glob("*")]:
        if p.is_file():
            lines = [l for l in p.read_text(errors="replace").splitlines() if l.strip() and not l.startswith("#")
                     and "=" not in l.split()[0]]
            for l in lines:
                add("cron", p, l, any(s in l for s in SUSPICIOUS_DIRS) or "curl" in l or "wget" in l or "base64" in l)
    for d in ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"):
        for p in Path("/etc", d).glob("*"):
            if p.is_file() and _recent(p, days):
                add("cron", p, "script programado", True)
    # systemd: unidades locales (no de paquetes) y de usuario
    for base in (Path("/etc/systemd/system"), *[h / ".config/systemd/user" for h in homes()]):
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in (".service", ".timer", ".socket", ".path") and not p.is_symlink():
                exec_line = next((l for l in p.read_text(errors="replace").splitlines() if l.startswith("ExecStart")), "")
                pkg = _owner_pkg(str(p)) if base == Path("/etc/systemd/system") else ""
                if not pkg:
                    add("systemd", p, exec_line, any(s in exec_line for s in SUSPICIOUS_DIRS))
    # arranque clásico y perfiles de shell
    for p in [Path("/etc/rc.local"), *Path("/etc/profile.d").glob("*"), Path("/etc/profile"), Path("/etc/bash.bashrc")]:
        if p.is_file() and (p.name == "rc.local" or _recent(p, days)):
            add("arranque/shell", p, "se ejecuta al iniciar o al abrir sesión")
    for h in homes():
        for name in (".bashrc", ".profile", ".bash_profile", ".zshrc", ".bash_logout", ".config/autostart"):
            p = h / name
            if p.is_file() and _recent(p, days):
                add("shell de usuario", p, "modificado recientemente", True)
            elif p.is_dir():
                for q in p.glob("*.desktop"):
                    add("autoarranque gráfico", q, next((l for l in q.read_text(errors="replace").splitlines()
                                                         if l.startswith("Exec=")), ""))
        ak = h / ".ssh" / "authorized_keys"
        if ak.exists():
            n = len([l for l in ak.read_text(errors="replace").splitlines() if l.strip() and not l.startswith("#")])
            add("clave SSH", ak, f"{n} claves" + (" (enlace simbólico)" if ak.is_symlink() else ""), ak.is_symlink())
    # precarga de librerías, sudoers, módulos del kernel
    pre = Path("/etc/ld.so.preload")
    if pre.exists() and pre.read_text().strip():
        add("precarga de librerías", pre, pre.read_text().strip(), True)
    for p in Path("/etc/sudoers.d").glob("*"):
        if _recent(p, days):
            add("sudoers", p, "regla de sudo modificada recientemente", True)
    if Path("/proc/modules").exists():
        for line in Path("/proc/modules").read_text().splitlines():
            name = line.split()[0]
            if "(OE)" in line or "(E)" in line or "(O)" in line:
                add("módulo del kernel", Path("/proc/modules"), f"{name}: fuera del árbol del kernel o sin firmar",
                    "(E)" in line)
    if system.has_cmd("atq"):
        jobs = system.run(["atq"]).out.strip()
        if jobs:
            rows.append(["at", "atq", jobs.replace("\n", " | ")[:90], "-", "!"])
    return rows


def suspicious_processes() -> list[list[str]]:
    rows = []
    for pid in (p for p in os.listdir("/proc") if p.isdigit()):
        base = Path("/proc", pid)
        try:
            exe = os.readlink(base / "exe")
        except OSError:
            continue
        try:
            cmd = (base / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            user = _username(base.stat().st_uid)
        except OSError:
            continue
        reasons = []
        if exe.startswith("/memfd:"):
            reasons.append("se ejecuta desde memoria (memfd), sin fichero en disco")
        elif exe.endswith(" (deleted)"):
            reasons.append("su ejecutable se ha borrado del disco")
        if exe.startswith(SUSPICIOUS_DIRS):
            reasons.append("se ejecuta desde una carpeta temporal")
        if "/." in exe:
            reasons.append("se ejecuta desde una carpeta oculta")
        if reasons:
            rows.append([pid, user, exe[:60], cmd[:60], "; ".join(reasons)])
    return rows


def _username(uid: int) -> str:
    import pwd
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


# ------------------------------------------------------------------ acciones

def persistencia(ctx: Context, v: dict) -> bool:
    days = int(v.get("dias") or 7)
    rows = persistence(days)
    flagged = [r for r in rows if r[4]]
    ctx.out.title(f"Mecanismos de persistencia ({len(rows)} encontrados, {len(flagged)} a revisar)")
    ctx.out.table(["", "Tipo", "Dónde", "Qué ejecuta / detalle", "Modificado"],
                  [[r[4], r[0], r[1], r[2], r[3]] for r in sorted(rows, key=lambda r: (r[4] != "!", r[0]))])
    ctx.out.info(f"'!' = modificado en los últimos {days} días o con señales sospechosas "
                 "(carpetas temporales, descargas, base64, enlaces simbólicos).")
    ctx.out.info("Que algo aparezca aquí no significa que sea malicioso: compáralo con lo que debería haber.")
    audit.record("triaje_persistencia", system.hostname(), "OK", f"{len(rows)} mecanismos, {len(flagged)} marcados")
    return True


def procesos(ctx: Context, v: dict) -> bool:
    rows = suspicious_processes()
    if rows:
        ctx.out.title(f"{len(rows)} procesos a revisar")
        ctx.out.table(["PID", "Usuario", "Ejecutable", "Comando", "Motivo"], rows)
    else:
        ctx.out.ok("Ningún proceso desde carpetas temporales, ocultas o con el ejecutable borrado.")
    if system.has_cmd("ss"):
        ctx.out.title("Programas que aceptan conexiones desde la red")
        r = system.run(["ss", "-ltnupH"], c_locale=True)
        out = []
        for line in r.out.splitlines():
            f = line.split()
            if len(f) > 4 and not f[4].startswith(("127.", "[::1]", "::1")):
                proc = line.split('users:(("', 1)[1].split('"', 1)[0] if 'users:(("' in line else "?"
                out.append([f[0], f[4], proc])
        ctx.out.table(["Proto", "Escucha en", "Programa"], out)
    ctx.out.title("Los 8 procesos que más CPU usan")
    r = system.run(["ps", "-eo", "pid,user:16,%cpu,%mem,etime,comm", "--sort=-%cpu"], c_locale=True)
    for line in r.out.splitlines()[:9]:
        ctx.out.line(line)
    return True


def recientes(ctx: Context, v: dict) -> bool:
    days = int(v.get("dias") or 2)
    ctx.out.title("Ejecutables en carpetas temporales")
    r = system.run(["find", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-type", "f", "-perm", "/111"], timeout=60)
    exe = [l for l in r.out.splitlines() if l.strip()]
    for l in exe[:40]:
        ctx.out.line(f"  {_when(Path(l))}  {l}")
    if not exe:
        ctx.out.ok("Ninguno.")
    ctx.out.title(f"Ficheros de /etc, /usr/bin y /usr/sbin modificados en {days} días")
    r = system.run(["find", "/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "-xdev", "-type", "f",
                    "-mtime", f"-{days}"], timeout=120)
    files = [l for l in r.out.splitlines() if l.strip()]
    for l in files[:60]:
        ctx.out.line(f"  {_when(Path(l))}  {l}")
    ctx.out.info(f"{len(files)} ficheros. Las actualizaciones del sistema también aparecen aquí: "
                 "compáralo con Registros › Buscar 'install'.")
    ctx.out.title("Ficheros SUID que no pertenecen a ningún paquete")
    r = system.run(["find", "/", "-xdev", "-type", "f", "-perm", "-4000"], timeout=300)
    odd = [p for p in r.out.splitlines() if p.strip() and not _owner_pkg(p)]
    for p in odd[:30]:
        ctx.out.line(f"  {_when(Path(p))}  {p}")
    if not odd:
        ctx.out.ok("Ninguno: todos los SUID son de paquetes del sistema.")
    else:
        ctx.out.warn("Un SUID fuera de paquetes puede ser una puerta trasera para hacerse root.")
    return True


COLLECT_CMDS = [  # orden de volatilidad
    ("procesos.txt", ["ps", "auxwwf"]),
    ("conexiones.txt", ["ss", "-tanup"]),
    ("escuchando.txt", ["ss", "-ltnup"]),
    ("sesiones.txt", ["who", "-a"]),
    ("loginctl.txt", ["loginctl", "list-sessions"]),
    ("modulos_kernel.txt", ["lsmod"]),
    ("ip_addr.txt", ["ip", "addr"]),
    ("ip_route.txt", ["ip", "route"]),
    ("arp.txt", ["ip", "neigh"]),
    ("montajes.txt", ["findmnt"]),
    ("firewall_nft.txt", ["nft", "list", "ruleset"]),
    ("firewall_iptables.txt", ["iptables-save"]),
    ("servicios.txt", ["systemctl", "list-units", "--all", "--no-pager"]),
    ("timers.txt", ["systemctl", "list-timers", "--all", "--no-pager"]),
    ("ultimos_accesos.txt", ["last", "-w", "-F"]),
    ("paquetes.txt", ["dpkg", "-l"]),
    ("journal_3dias.txt", ["journalctl", "--since", "3 days ago", "--no-pager", "-o", "short-iso"]),
]
COLLECT_PATHS = ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d", "/etc/crontab", "/etc/cron.d",
                 "/var/spool/cron", "/etc/systemd/system", "/etc/rc.local", "/etc/ld.so.preload", "/etc/hosts",
                 "/etc/resolv.conf", "/etc/ssh/sshd_config", "/etc/profile.d", "/var/log/auth.log", "/var/log/secure",
                 "/var/log/syslog"]


def evidencias(ctx: Context, v: dict) -> bool:
    d = results.new_dir("triaje", f"evidencias_{system.hostname()}")
    work = d / "datos"
    work.mkdir(mode=0o700)
    ctx.out.info("Recogiendo (primero lo más volátil: procesos y conexiones)...")
    for name, cmd in COLLECT_CMDS:
        if system.has_cmd(cmd[0]):
            r = system.run(cmd, c_locale=True, timeout=300)
            (work / name).write_text(r.out + (("\n# stderr\n" + r.err) if r.err else ""), errors="replace")
            ctx.out.line(f"  ✓ {name}")
    files_dir = work / "ficheros"
    files_dir.mkdir()
    for p in COLLECT_PATHS + [str(h / n) for h in homes() for n in (".bash_history", ".zsh_history",
                                                                     ".ssh/authorized_keys", ".bashrc", ".profile")]:
        src = Path(p)
        if not src.exists() or src.is_symlink():
            continue
        dest = files_dir / p.lstrip("/")
        try:
            if src.is_dir():
                shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
        except OSError as e:
            ctx.out.warn(f"No se pudo copiar {p}: {e}")
    ctx.out.line("  ✓ ficheros de configuración, historiales y registros")
    manifest = []
    for p in sorted(work.rglob("*")):
        if p.is_file():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest.append(f"{h}  {p.relative_to(work)}")
    (work / "MANIFIESTO.sha256").write_text("\n".join(manifest) + "\n")
    info = (f"Equipo: {system.hostname()}\nSistema: {system.os_pretty()}\nRecogido por: {system.operator()}\n"
            f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\nMotivo: {v.get('motivo') or '-'}\n")
    (work / "LEEME.txt").write_text(info)
    bundle = d / f"evidencias_{system.hostname()}_{time.strftime('%Y%m%d_%H%M%S')}.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        tar.add(work, arcname=bundle.name.removesuffix(".tar.gz"))
    shutil.rmtree(work)
    os.chmod(bundle, 0o600)
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    results.write(d / "paquete.sha256", f"{digest}  {bundle.name}\n")
    audit.record("triaje_evidencias", system.hostname(), "OK", f"{bundle} sha256={digest[:16]}... motivo={v.get('motivo') or '-'}")
    ctx.out.ok(f"Evidencias: {bundle} ({bundle.stat().st_size // 1024} KB, {len(manifest)} ficheros)")
    ctx.out.info(f"SHA-256 del paquete: {digest}")
    ctx.out.info("Cópialo fuera del equipo cuanto antes y anota el hash para la cadena de custodia.")
    return True


class Triaje(Module):
    full = True
    id = "triaje"
    name = "Triaje de incidentes"
    category = "Blue team"
    summary = "Persistencia, procesos sospechosos, ficheros recientes y recogida de evidencias"
    help = """\
# Triaje de incidentes

Para cuando sospechas que un equipo puede estar comprometido. **Solo lee**: no borra ni detiene nada,
para no destruir pruebas.

- **Persistencia**: todo lo que se ejecuta solo (cron, servicios de systemd locales y de usuario,
  scripts de arranque, perfiles de shell, autoarranque gráfico, claves SSH, precarga de librerías,
  sudoers, módulos del kernel fuera del árbol, tareas `at`). Marca con **!** lo modificado
  recientemente o con señales típicas de ataque (carpetas temporales, descargas, base64).
- **Procesos sospechosos**: programas que se ejecutan desde carpetas temporales u ocultas o cuyo
  ejecutable se ha borrado (técnica habitual de malware), qué escucha en la red y qué consume CPU.
- **Ficheros recientes**: ejecutables en /tmp, cambios recientes en /etc y en binarios del sistema,
  y ficheros SUID que no son de ningún paquete.
- **Recoger evidencias**: crea un paquete con procesos, conexiones, sesiones, servicios, registros,
  configuración, historiales y claves, con un **manifiesto SHA-256** de cada fichero y el hash del
  paquete. Sácalo del equipo cuanto antes.

Un aviso no es una prueba de compromiso: compáralo con lo que sabes que debería haber en el equipo.
"""

    def actions(self):
        dias = Param("dias", "Marcar lo modificado en los últimos N días", "int", 7, required=False)
        return [
            Action("persistencia", "Persistencia", persistencia, params=[dias]),
            Action("procesos", "Procesos sospechosos", procesos),
            Action("recientes", "Ficheros recientes y SUID", recientes,
                   params=[Param("dias", "Días hacia atrás", "int", 2, required=False)]),
            Action("evidencias", "Recoger evidencias", evidencias,
                   params=[Param("motivo", "Motivo o referencia del incidente", required=False)],
                   help="Paquete comprimido con todo lo relevante y su manifiesto de hashes."),
        ]
