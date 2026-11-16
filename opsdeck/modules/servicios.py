"""Servicios (systemd): ver, arrancar, parar, reiniciar, activar al inicio y tareas programadas (timers)."""

from __future__ import annotations

import re

from ..core import system
from ..core.catalog import Action, Context, Module, Param, file
from ..core.ops import apply

UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]+$")
# Servicios cuya parada puede cortar el acceso de quien está usando la herramienta
REMOTE_ACCESS = ("ssh", "sshd", "xrdp", "xrdp-sesman", "networking", "NetworkManager", "systemd-networkd")


def unit_name(name: str) -> str:
    name = name.strip()
    return name if "." in name else f"{name}.service"


def service_names() -> list[str]:
    r = system.run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain"], c_locale=True)
    return sorted({l.split()[0].removesuffix(".service") for l in r.out.splitlines() if l.strip()})


def _valid(ctx, name) -> str:
    if not UNIT_RE.match(name or ""):
        ctx.out.error("Nombre de servicio no válido")
        return ""
    u = unit_name(name)
    if not system.run(["systemctl", "list-unit-files", u, "--no-legend"], c_locale=True).out.strip() and \
            not system.run(["systemctl", "status", u], c_locale=True).out.strip():
        ctx.out.error(f"No existe el servicio '{name}'")
        return ""
    return u


def resumen(ctx: Context, v: dict) -> bool:
    units = system.run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"], c_locale=True)
    rows = [l.split(None, 4) for l in units.out.splitlines() if l.strip()]
    running = [r for r in rows if len(r) > 3 and r[3] == "running"]
    failed = [r for r in rows if len(r) > 2 and r[2] == "failed"]
    enabled = system.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"],
                         c_locale=True).out.splitlines()
    ctx.out.table(["Dato", "Valor"], [["En marcha", str(len(running))], ["Con fallos", str(len(failed))],
                                     ["Se inician al arrancar", str(len(enabled))]])
    if failed:
        ctx.out.title("Con fallos")
        ctx.out.table(["Servicio", "Descripción"], [[r[0], r[4] if len(r) > 4 else ""] for r in failed])
        ctx.out.info("Para ver el motivo: acción 'Estado y registros de un servicio'.")
    else:
        ctx.out.ok("Ningún servicio con fallos.")
    return True


def listar(ctx: Context, v: dict) -> bool:
    which = v.get("filtro", "activos")
    if which == "arranque":
        r = system.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain"],
                       c_locale=True)
        ctx.out.table(["Servicio", "Al arrancar"], [l.split()[:2] for l in r.out.splitlines() if l.strip()])
        return True
    args = {"activos": ["--state=running"], "fallidos": ["--state=failed"], "todos": ["--all"]}[which]
    r = system.run(["systemctl", "list-units", "--type=service", *args, "--no-legend", "--plain"], c_locale=True)
    rows = [(l.split(None, 4) + [""] * 5)[:5] for l in r.out.splitlines() if l.strip()]
    ctx.out.table(["Servicio", "Estado", "Detalle", "Descripción"], [[x[0].removesuffix(".service"), x[2], x[3], x[4]]
                                                                     for x in rows])
    ctx.out.info(f"{len(rows)} servicios.")
    return True


def estado(ctx: Context, v: dict) -> bool:
    u = _valid(ctx, v["servicio"])
    if not u:
        return False
    st = system.run(["systemctl", "status", "--no-pager", "-n", "0", u], c_locale=True)
    for line in st.out.splitlines()[:12]:
        ctx.out.line(line)
    ctx.out.title(f"Últimas {v.get('lineas', 30)} líneas de registro")
    lg = system.run(["journalctl", "-u", u, "-n", str(v.get("lineas", 30)), "--no-pager", "-q"], c_locale=True)
    for line in lg.out.splitlines():
        ctx.out.line(line)
    return True


def _control(verb: str, label: str):
    def run(ctx: Context, v: dict) -> bool:
        u = _valid(ctx, v["servicio"])
        if not u:
            return False
        ok = apply(ctx, f"servicio_{verb}", u, ["systemctl", verb, u])
        if ok:
            state = system.run(["systemctl", "is-active", u], c_locale=True).out.strip()
            boot = system.run(["systemctl", "is-enabled", u], c_locale=True).out.strip()
            ctx.out.ok(f"{u}: {label}. Ahora: {state}, al arrancar: {boot}")
        return ok
    return run


def _confirm_stop(v: dict) -> str:
    name = v.get("servicio", "").removesuffix(".service")
    if name in REMOTE_ACCESS:
        return (f"'{name}' da acceso remoto o red a este equipo. Si estás conectado a través de él, "
                "PERDERÁS LA CONEXIÓN. ¿Continuar?")
    return f"Se detendrá/reiniciará '{name}'. ¿Continuar?"


def timers(ctx: Context, v: dict) -> bool:
    r = system.run(["systemctl", "list-timers", "--all", "--no-legend"], c_locale=True)
    rows = []
    for line in r.out.splitlines():
        m = re.search(r"(\S+\.timer)\s+(\S+\.service|\S+)\s*$", line)
        if not m:
            continue
        before = line[:m.start()].split()
        nxt = " ".join(before[:4]) if before and before[0] not in ("-", "n/a") else "-"
        rows.append([m.group(1).removesuffix(".timer"), nxt, m.group(2)])
    ctx.out.title("Tareas programadas de systemd (timers)")
    ctx.out.table(["Timer", "Próxima ejecución", "Ejecuta"], rows)
    ctx.out.info("Las tareas de cron se revisan en Blue team › Triaje (persistencia).")
    return True


class Servicios(Module):
    id = "servicios"
    name = "Servicios"
    category = "Sistemas"
    summary = "Servicios del sistema (systemd): estado, registros, arrancar, parar y tareas programadas"
    requires = [file("/run/systemd/system", label="systemd en ejecución")]
    help = """\
# Servicios

Los **servicios** son los programas que funcionan en segundo plano (servidor SSH, escritorio remoto,
bases de datos...). Este módulo usa systemd, el gestor de servicios de casi todos los Linux actuales.

- **Resumen** y **Listar**: qué está en marcha, qué ha fallado y qué arranca con el equipo.
- **Estado y registros**: lo primero que hay que mirar cuando algo no funciona; incluye las últimas
  líneas que ha escrito el servicio.
- **Iniciar / Detener / Reiniciar / Recargar**: *recargar* aplica cambios de configuración sin cortar
  el servicio (si lo admite).
- **Activar / Desactivar al arrancar**: no lo arranca ni lo para ahora, solo cambia lo que pasará
  en el próximo inicio.
- **Tareas programadas**: los *timers* de systemd (equivalentes modernos de cron).

> Cuidado con **ssh** y **xrdp**: si los detienes mientras estás conectado por ellos, pierdes la
> conexión. La herramienta te avisa antes.
"""

    def actions(self):
        svc = Param("servicio", "Servicio", suggest=service_names, help="Nombre del servicio, p. ej. ssh, xrdp, cron")
        return [
            Action("resumen", "Resumen", resumen, help="Cuántos servicios hay en marcha, cuáles han fallado."),
            Action("listar", "Listar servicios", listar, params=[Param("filtro", "Mostrar", "choice", "activos", choices=[
                ("activos", "En marcha"), ("fallidos", "Con fallos"), ("arranque", "Los que se inician al arrancar"),
                ("todos", "Todos")])]),
            Action("estado", "Estado y registros de un servicio", estado,
                   params=[svc, Param("lineas", "Líneas de registro", "int", 30, required=False)],
                   help="Estado actual y últimas líneas de su registro: lo primero cuando algo falla."),
            Action("iniciar", "Iniciar", _control("start", "iniciado"), changes=True, params=[svc]),
            Action("detener", "Detener", _control("stop", "detenido"), changes=True, params=[svc],
                   confirm=_confirm_stop),
            Action("reiniciar", "Reiniciar", _control("restart", "reiniciado"), changes=True, params=[svc],
                   confirm=_confirm_stop),
            Action("recargar", "Recargar configuración", _control("reload", "configuración recargada"),
                   changes=True, params=[svc], help="Aplica cambios de configuración sin cortar el servicio."),
            Action("habilitar", "Activar al arrancar", _control("enable", "se iniciará al arrancar"),
                   changes=True, params=[svc]),
            Action("deshabilitar", "Desactivar al arrancar", _control("disable", "no se iniciará al arrancar"),
                   changes=True, params=[svc], confirm=lambda v: _confirm_stop(v).replace(
                       "Se detendrá/reiniciará", "No arrancará en el próximo inicio:")),
            Action("timers", "Tareas programadas (timers)", timers),
        ]
