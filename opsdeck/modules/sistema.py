"""Sistema: resumen del equipo, puertos en escucha, servicios con fallos y actualizaciones."""

from __future__ import annotations

import os
import time
from pathlib import Path

from ..core import audit, packages, system
from ..core.catalog import Action, Context, Module


def _uptime() -> str:
    try:
        secs = int(float(Path("/proc/uptime").read_text().split()[0]))
    except OSError:
        return "?"
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    return f"{d} d {h} h {r // 60} min"


def _mem() -> str:
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0])
    except OSError:
        return "?"
    total, avail = info.get("MemTotal", 0), info.get("MemAvailable", 0)
    return f"{(total - avail) / 1048576:.1f} de {total / 1048576:.1f} GB en uso"


def _listening() -> list[list[str]]:
    if not system.has_cmd("ss"):
        return []
    r = system.run(["ss", "-ltnupH"], c_locale=True)
    rows = []
    for line in r.out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proc = ""
        if "users:((" in line:
            proc = line.split('users:(("', 1)[1].split('"', 1)[0]
        local = f[4]
        addr, _, port = local.rpartition(":")
        exposure = "solo local" if addr.strip("[]") in ("127.0.0.1", "::1", "127.0.0.53%lo", "127.0.0.54") \
            or addr.startswith("127.") else "red"
        rows.append([f[0], port, addr or "*", proc or "?", exposure])
    rows.sort(key=lambda r: (r[0], int(r[1]) if r[1].isdigit() else 0))
    return rows


def resumen(ctx: Context, v: dict) -> bool:
    o = ctx.out
    o.title(f"{system.hostname()} · {system.os_pretty()}")
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    rows = [
        ["Kernel", os.uname().release],
        ["Encendido desde hace", _uptime()],
        ["CPU", f"{os.cpu_count()} núcleos · carga {load[0]:.2f} {load[1]:.2f} {load[2]:.2f}"],
        ["Memoria", _mem()],
        ["Gestor de paquetes", packages.manager().name],
        ["systemd", "sí" if system.systemd_available() else "no"],
    ]
    o.table(["Dato", "Valor"], rows)
    if system.has_cmd("df"):
        r = system.run(["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"], c_locale=True)
        disks = [l.split() for l in r.out.splitlines()[1:] if l.strip()]
        o.title("Discos")
        o.table(["Dispositivo", "Tipo", "Tamaño", "Usado", "Libre", "Uso", "Montado en"],
                [d[:7] for d in disks if len(d) >= 7])
        for d in disks:
            if len(d) >= 7 and d[5].rstrip("%").isdigit() and int(d[5].rstrip("%")) >= 90:
                o.warn(f"{d[6]} está al {d[5]}")
    if system.has_cmd("ip"):
        r = system.run(["ip", "-br", "addr"], c_locale=True)
        o.title("Red")
        o.table(["Interfaz", "Estado", "Direcciones"],
                [[f[0], f[1], " ".join(f[2:])] for f in (l.split() for l in r.out.splitlines()) if len(f) >= 2 and f[0] != "lo"])
    ports = _listening()
    exposed = [p for p in ports if p[4] == "red"]
    o.info(f"Puertos en escucha: {len(ports)} ({len(exposed)} accesibles desde la red). Detalle en 'Puertos en escucha'.")
    if system.systemd_available():
        failed = system.run(["systemctl", "--failed", "--no-legend", "--plain"], c_locale=True).out.split("\n")
        failed = [l.split()[0] for l in failed if l.strip()]
        (o.warn if failed else o.ok)(f"Servicios con fallos: {', '.join(failed) if failed else 'ninguno'}")
    return True


def puertos(ctx: Context, v: dict) -> bool:
    rows = _listening()
    if not rows:
        ctx.out.warn("No se pudo obtener la lista (falta 'ss' o no hay puertos en escucha).")
        return True
    ctx.out.title("Puertos en escucha")
    ctx.out.table(["Proto", "Puerto", "Dirección", "Proceso", "Alcance"], rows)
    ctx.out.info("'red' = se puede conectar desde otros equipos. 'solo local' = solo desde este equipo.")
    return True


def servicios(ctx: Context, v: dict) -> bool:
    if not system.systemd_available():
        ctx.out.warn("Este sistema no usa systemd.")
        return True
    r = system.run(["systemctl", "--failed", "--no-legend", "--plain"], c_locale=True)
    rows = [l.split(None, 4) for l in r.out.splitlines() if l.strip()]
    if not rows:
        ctx.out.ok("No hay servicios con fallos.")
        return True
    ctx.out.title("Servicios con fallos")
    ctx.out.table(["Unidad", "Carga", "Activo", "Estado", "Descripción"], [(x + [""] * 5)[:5] for x in rows])
    ctx.out.info("Para ver el motivo: journalctl -u <unidad> -n 50")
    return True


def pendientes(ctx: Context, v: dict) -> bool:
    pm = packages.manager()
    if pm.name != "apt":
        ctx.out.warn(f"Consulta de actualizaciones aún no disponible para {pm.name}.")
        return True
    pm.refresh(ctx.out.line)
    pk = pm.upgradable()
    if not pk:
        ctx.out.ok("El sistema está al día.")
        return True
    ctx.out.title(f"{len(pk)} paquetes con actualización")
    ctx.out.line(" ".join(pk[:200]) + (" ..." if len(pk) > 200 else ""))
    ctx.out.info("Para instalarlas: acción 'Instalar actualizaciones'.")
    return True


def actualizar(ctx: Context, v: dict) -> bool:
    pm = packages.manager()
    if pm.name != "apt":
        ctx.out.warn(f"Actualización aún no disponible para {pm.name}.")
        return False
    pm.refresh(ctx.out.line, max_age_h=0)
    n = len(pm.upgradable())
    if not n:
        ctx.out.ok("No hay nada que actualizar.")
        return True
    t0 = time.time()
    rc = pm.upgrade(ctx.out.line)
    audit.record("actualizar_sistema", system.hostname(), "OK" if rc == 0 else f"ERROR_{rc}", f"paquetes={n}")
    (ctx.out.ok if rc == 0 else ctx.out.error)(
        f"Actualización {'completada' if rc == 0 else 'con errores'} en {int(time.time() - t0)} s")
    if os.path.exists("/var/run/reboot-required"):
        ctx.out.warn("El sistema pide un reinicio para aplicar algunas actualizaciones.")
    return rc == 0


class Sistema(Module):
    id = "sistema"
    name = "Sistema"
    category = "Sistemas"
    summary = "Resumen del equipo, puertos, servicios y actualizaciones"
    help = """\
# Sistema

Vista rápida del estado del equipo. Las acciones de consulta no cambian nada.

- **Resumen**: sistema operativo, memoria, discos (avisa si alguno pasa del 90 %),
  direcciones de red, puertos abiertos y servicios con fallos.
- **Puertos en escucha**: qué programas aceptan conexiones y si lo hacen
  *solo desde este equipo* o *desde la red*. Un puerto "red" que no reconozcas merece revisión.
- **Servicios con fallos**: servicios de systemd que no han arrancado bien.
- **Actualizaciones pendientes**: consulta (sin instalar nada) qué paquetes tienen versión nueva.
- **Instalar actualizaciones**: instala todas las pendientes. Pide confirmación.
  Si alguna requiere reiniciar, te avisa; el reinicio lo decides tú.
"""

    def actions(self):
        return [
            Action("resumen", "Resumen del equipo", resumen,
                   help="Estado general: sistema, memoria, discos, red, puertos y servicios."),
            Action("puertos", "Puertos en escucha", puertos,
                   help="Programas que aceptan conexiones y desde dónde se puede llegar a ellos."),
            Action("servicios", "Servicios con fallos", servicios,
                   help="Unidades de systemd en estado 'failed' y cómo ver el motivo."),
            Action("pendientes", "Actualizaciones pendientes", pendientes,
                   help="Actualiza el índice de paquetes si es antiguo y lista lo que se puede actualizar. No instala nada."),
            Action("actualizar", "Instalar actualizaciones", actualizar, changes=True,
                   confirm="Se instalarán todas las actualizaciones pendientes del sistema. ¿Continuar?",
                   help="Equivale a 'apt-get update && apt-get upgrade'. No reinicia el equipo."),
        ]
