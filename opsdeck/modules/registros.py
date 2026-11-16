"""Registros: errores recientes, accesos fallidos y correctos, uso de sudo y búsqueda en el journal."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

from ..core import system
from ..core.catalog import Action, Context, Module, Param, cmd

PERIODS = [("1h", "Última hora"), ("24h", "Últimas 24 horas"), ("7d", "Últimos 7 días"), ("30d", "Últimos 30 días")]
SINCE = {"1h": "1 hour ago", "24h": "24 hours ago", "7d": "7 days ago", "30d": "30 days ago"}
MAX_LINES = 200000

# Patrones de intentos fallidos (SSH, PAM genérico, xrdp, sudo, su)
FAIL = [
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*).*?\buser=(?P<user>\S+)"),
    re.compile(r"AUTHFAIL: user=(?P<user>\S+) ip=(?:::ffff:)?(?P<ip>\S+)"),
    re.compile(r"FAILED SU \(to \S+\) (?P<user>\S+)"),
    re.compile(r"(?P<user>\S+) : (?:\d+ )?incorrect password attempts?"),
]
OK = [
    re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"(?:session started|login successful) for user:? ?(?P<user>\S+)", re.I),
]
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?(?:TTY=(?P<tty>\S+) ; )?.*?USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.+)$")


def journal(since: str, extra: list[str] | None = None) -> Iterator[dict]:
    """Entradas del journal como diccionarios (MESSAGE, SYSLOG_IDENTIFIER, _COMM, hora...)."""
    r = system.run(["journalctl", "--since", since, "-o", "json", "--no-pager", "-q", *(extra or [])], timeout=180)
    for i, line in enumerate(r.out.splitlines()):
        if i >= MAX_LINES:
            break
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = e.get("MESSAGE", "")
        if isinstance(msg, list):          # mensajes binarios
            msg = bytes(msg).decode(errors="replace")
        e["MESSAGE"] = msg
        yield e


def stamp(e: dict) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(e["__REALTIME_TIMESTAMP"]) / 1e6))
    except (KeyError, ValueError):
        return "?"


def classic_lines() -> list[str]:
    """Sin journal: /var/log/auth.log o /var/log/secure."""
    for f in ("/var/log/auth.log", "/var/log/secure"):
        try:
            return Path(f).read_text(errors="replace").splitlines()[-MAX_LINES:]
        except OSError:
            continue
    return []


def _messages(since_key: str) -> list[tuple[str, str]]:
    if system.has_cmd("journalctl"):
        return [(stamp(e), e["MESSAGE"]) for e in journal(SINCE[since_key])]
    return [(l[:15], l) for l in classic_lines()]


def parse_failures(msgs: list[tuple[str, str]]) -> list[dict]:
    out = []
    for when, m in msgs:
        for pat in FAIL:
            x = pat.search(m)
            if x:
                d = x.groupdict()
                out.append({"fecha": when, "usuario": d.get("user", "?"), "ip": (d.get("ip") or "local").strip(),
                            "msg": m})
                break
    return out


def parse_logins(msgs: list[tuple[str, str]]) -> list[dict]:
    out = []
    for when, m in msgs:
        for pat in OK:
            x = pat.search(m)
            if x:
                d = x.groupdict()
                out.append({"fecha": when, "usuario": d.get("user", "?"), "ip": d.get("ip") or "-",
                            "metodo": d.get("method") or ("rdp" if "session" in m.lower() or "login" in m.lower() else "-")})
                break
    return out


# ------------------------------------------------------------------ acciones

def errores(ctx: Context, v: dict) -> bool:
    if not system.has_cmd("journalctl"):
        ctx.out.warn("Este sistema no tiene journal.")
        return False
    entries = list(journal(SINCE[v["periodo"]], ["-p", "err"]))
    if not entries:
        ctx.out.ok("Sin errores en el periodo.")
        return True
    src = Counter(e.get("_SYSTEMD_UNIT") or e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "?" for e in entries)
    ctx.out.title(f"{len(entries)} errores · origen más frecuente")
    ctx.out.table(["Origen", "Errores"], [[k, str(n)] for k, n in src.most_common(12)])
    ctx.out.title("Los 25 más recientes")
    for e in entries[-25:]:
        ctx.out.line(f"{stamp(e)}  {e.get('SYSLOG_IDENTIFIER', '?')}: {e['MESSAGE'][:200]}")
    return True


def fallidos(ctx: Context, v: dict) -> bool:
    fails = parse_failures(_messages(v["periodo"]))
    if not fails:
        ctx.out.ok("No hay intentos de acceso fallidos en el periodo.")
        return True
    by_ip = Counter(f["ip"] for f in fails)
    by_user = Counter(f["usuario"] for f in fails)
    ctx.out.title(f"{len(fails)} intentos fallidos")
    ctx.out.table(["Origen (IP)", "Intentos"], [[k, str(n)] for k, n in by_ip.most_common(15)])
    ctx.out.table(["Usuario intentado", "Intentos"], [[k, str(n)] for k, n in by_user.most_common(15)])
    noisy = [ip for ip, n in by_ip.items() if n >= 10 and ip not in ("local", "")]
    if noisy:
        ctx.out.warn("Orígenes con 10 o más fallos (posible fuerza bruta): " + ", ".join(noisy))
        ctx.out.info("Puedes cortarles el paso en Firewall, o limitar el servicio a tu red de administración.")
    ctx.out.title("Los 15 más recientes")
    for f in fails[-15:]:
        ctx.out.line(f"{f['fecha']}  {f['usuario']:<16} {f['ip']:<18} {f['msg'][:120]}")
    return True


def correctos(ctx: Context, v: dict) -> bool:
    logins = parse_logins(_messages(v["periodo"]))
    ctx.out.title("Accesos correctos (SSH y escritorio remoto)")
    if logins:
        ctx.out.table(["Fecha", "Usuario", "Origen", "Método"],
                      [[x["fecha"], x["usuario"], x["ip"], x["metodo"]] for x in logins[-40:]])
    else:
        ctx.out.info("Sin accesos por SSH/RDP en el periodo.")
    if system.has_cmd("last"):
        r = system.run(["last", "-w", "-n", "15"], c_locale=True)
        ctx.out.title("Últimas sesiones registradas (last)")
        for line in r.out.splitlines():
            if line.strip():
                ctx.out.line(line)
    return True


def sudo_uso(ctx: Context, v: dict) -> bool:
    rows = []
    if system.has_cmd("journalctl"):
        for e in journal(SINCE[v["periodo"]], ["_COMM=sudo"]):
            m = SUDO.search(e["MESSAGE"])
            if m:
                rows.append([stamp(e), m.group("user"), m.group("as"), m.group("cmd")[:100]])
    else:
        for when, msg in _messages(v["periodo"]):
            if "sudo:" in msg:
                m = SUDO.search(msg.split("sudo:", 1)[1])
                if m:
                    rows.append([when, m.group("user"), m.group("as"), m.group("cmd")[:100]])
    if not rows:
        ctx.out.info("No hay usos de sudo en el periodo.")
        return True
    ctx.out.title(f"{len(rows)} usos de sudo")
    ctx.out.table(["Usuario", "Veces"], [[k, str(n)] for k, n in Counter(r[1] for r in rows).most_common()])
    ctx.out.table(["Fecha", "Usuario", "Como", "Comando"], rows[-40:])
    return True


def buscar(ctx: Context, v: dict) -> bool:
    text = v["texto"].lower()
    extra = ["-u", v["servicio"]] if v.get("servicio") else []
    found = 0
    if system.has_cmd("journalctl"):
        for e in journal(SINCE[v["periodo"]], extra):
            if text in e["MESSAGE"].lower():
                found += 1
                if found <= 200:
                    ctx.out.line(f"{stamp(e)}  {e.get('SYSLOG_IDENTIFIER', '?')}: {e['MESSAGE'][:220]}")
    else:
        for when, m in _messages(v["periodo"]):
            if text in m.lower():
                found += 1
                if found <= 200:
                    ctx.out.line(m[:240])
    (ctx.out.info if found else ctx.out.warn)(f"{found} coincidencias" + (" (se muestran 200)" if found > 200 else ""))
    return True


class Registros(Module):
    id = "registros"
    name = "Registros"
    category = "Sistemas"
    summary = "Errores recientes, accesos fallidos y correctos, uso de sudo y búsqueda"
    requires = [cmd("journalctl", debian="systemd", label="journal de systemd")]
    help = """\
# Registros

Consulta lo que ha pasado en el equipo sin tener que conocer `journalctl` ni dónde está cada log.

- **Errores recientes**: errores del sistema agrupados por origen; útil cuando "algo va mal".
- **Accesos fallidos**: intentos de entrar con contraseña o usuario erróneo (SSH, escritorio remoto,
  sudo, su) agrupados por **IP de origen** y **usuario**. Muchos fallos desde una IP suele ser un
  ataque de fuerza bruta.
- **Accesos correctos**: quién ha entrado, desde dónde y cómo.
- **Uso de sudo**: qué comandos se han ejecutado como administrador y quién.
- **Buscar**: texto libre en los registros de un periodo (opcionalmente de un solo servicio).

Nota: si las conexiones pasan por un firewall con NAT, la IP de origen será la del firewall.
"""

    def actions(self):
        per = Param("periodo", "Periodo", "choice", "24h", choices=PERIODS)
        return [
            Action("errores", "Errores recientes", errores, params=[per]),
            Action("fallidos", "Accesos fallidos", fallidos, params=[per],
                   help="Intentos fallidos por IP y por usuario; señala posibles ataques de fuerza bruta."),
            Action("correctos", "Accesos correctos", correctos, params=[per]),
            Action("sudo", "Uso de sudo", sudo_uso, params=[per]),
            Action("buscar", "Buscar en los registros", buscar, params=[
                Param("texto", "Texto a buscar"), per,
                Param("servicio", "Solo de este servicio (opcional)", required=False)]),
        ]
