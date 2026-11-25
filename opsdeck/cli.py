"""Línea de comandos. Sin argumentos abre la interfaz visual.

  opsdeck                         interfaz visual
  opsdeck modulos                 catálogo y estado de cada módulo
  opsdeck ayuda [módulo] [acción] ayuda
  opsdeck instalar <módulo|todo> [--opcionales]
                                  instala lo que le falta a un módulo, o a todos (pide confirmación);
                                  --opcionales añade las herramientas que amplían el módulo
  opsdeck edicion                 edición instalada (ligera o completa) y quién accede a la completa
  opsdeck registro [n] [texto]    últimos cambios registrados
  opsdeck resultados [módulo]     escaneos, análisis e informes guardados
  opsdeck autoactualizar          descarga la última versión de la herramienta (git)
  opsdeck <módulo>                acciones del módulo
  opsdeck <módulo> <acción> [--dato valor ...] [--si]
                                  las contraseñas se piden sin eco con --password -
"""

from __future__ import annotations

import getpass
import sys

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import NAME, VERSION
from .core import accounts, audit, edition, installer, packages, paths, system
from .core.catalog import AVAILABLE, INSTALLABLE, Context, all_modules, module
from .core.ops import execute

console = Console(highlight=False)


class ConsoleOut:
    """Los mensajes llevan datos ajenos (banners, objetivos, títulos): se escapan para que rich no
    los interprete como marcado."""

    def info(self, m): console.print(f"[blue][*][/] {escape(str(m))}")
    def ok(self, m): console.print(f"[green][+][/] {escape(str(m))}")
    def warn(self, m): console.print(f"[yellow][!][/] {escape(str(m))}")
    def error(self, m): console.print(f"[red][-][/] {escape(str(m))}")
    def line(self, m=""): console.print(m, markup=False)
    def title(self, m): console.print(f"\n[bold]{escape(str(m))}[/]")

    def table(self, headers, rows):
        t = Table(*headers, show_edge=False, header_style="bold")
        for r in rows:
            t.add_row(*[escape(str(c)) for c in r])
        console.print(t)

    def secret(self, label, value):
        console.print(f"\n  [bold yellow]{escape(str(label))}:[/] [bold reverse] {escape(str(value))} [/]\n")

    def check(self, good, m):
        console.print(("  [green][OK][/] " if good else "  [red][X][/]  ") + escape(str(m)))


def _ask_yes(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(f"{question} [s/N] ").strip().lower().startswith("s")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _parse(tokens: list[str]) -> tuple[dict, bool]:
    values, yes, i = {}, False, 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("--si", "--yes", "-y"):
            yes = True
        elif t.startswith("--no-"):
            values[t[5:].replace("-", "_")] = False
        elif t.startswith("--"):
            key = t[2:]
            if "=" in key:
                key, val = key.split("=", 1)
                values[key.replace("-", "_")] = val
            elif i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                values[key.replace("-", "_")] = tokens[i + 1]
                i += 1
            else:
                values[key.replace("-", "_")] = True
        else:
            values.setdefault("_pos", []).append(t)
        i += 1
    return values, yes


def cmd_modulos() -> int:
    t = Table("Módulo", "Categoría", "Estado", "Detalle", show_edge=False, header_style="bold")
    for m in all_modules():
        st = m.status()
        color = {"disponible": "green", "instalable": "yellow"}.get(st.state, "red")
        detail = st.reason + (f"  →  {NAME} instalar {m.id}" if st.state == INSTALLABLE else "")
        opt = m.missing_optional() if st.state == AVAILABLE else []
        if opt:
            detail = (detail or m.summary) + f"  (+{len(opt)} opcionales: {NAME} instalar {m.id} --opcionales)"
        t.add_row(f"{m.id} ({m.name})", m.category, f"[{color}]{st.state}[/]", escape(detail or m.summary))
    console.print(t)
    return 0


def cmd_ayuda(args: list[str]) -> int:
    if not args:
        console.print(Markdown(paths.HELP_FILE.read_text(encoding="utf-8") if paths.HELP_FILE.exists()
                               else __doc__ or ""))
        return 0
    m = module(args[0])
    if not m:
        console.print(f"[red]No existe el módulo '{escape(args[0])}'[/]")
        return 1
    if len(args) > 1:
        a = m.action(args[1])
        if not a:
            console.print(f"[red]El módulo {m.id} no tiene la acción '{escape(args[1])}'[/]")
            return 1
        console.print(f"\n[bold]{m.name} › {a.label}[/]\n{a.help}\n")
        for title, group in (("", a.basic_params()), ("Opciones avanzadas", a.advanced_params())):
            if not group:
                continue
            if title:
                console.print(f"\n[bold]{title}[/] (opcionales)")
            for p in group:
                req = "" if p.required and p.kind != "bool" else " (opcional)"
                extra = ("  valores: " + ", ".join(c[0] or "''" for c in p.choices)) if p.choices else ""
                console.print(f"  --{p.name:<16} {p.label}{req}{extra}" + (f"\n{'':20}{p.help}" if p.help else ""),
                              markup=False)
        console.print("\nUn valor que empieza por guion va con '=': --opciones='-sS -p 80'", markup=False)
        console.print(f"\nEjemplo: {NAME} {m.id} {a.id} " +
                      " ".join(f"--{p.name} ..." for p in a.visible_params() if p.required and p.kind != "bool"))
        return 0
    console.print(Markdown(m.help))
    return cmd_acciones(m)


def cmd_acciones(m) -> int:
    t = Table("Acción", "Qué hace", show_edge=False, header_style="bold")
    group = None
    for a in m.actions():
        if a.available():
            if a.group and a.group != group:
                group = a.group
                t.add_row(f"[bold dim]{group.upper()}[/]", "")
            t.add_row(a.id, a.label + (" [yellow](cambia el sistema)[/]" if a.changes else ""))
    console.print(t)
    console.print(f"Más detalle: {NAME} ayuda {m.id} <acción>")
    return 0


def cmd_edicion() -> int:
    ed = edition.current()
    console.print(f"Edición instalada: [bold]{ed}[/]")
    if ed == edition.FULL:
        g = accounts.group(edition.group())
        ok, why = edition.allowed_full()
        console.print(f"Grupo con acceso a los módulos avanzados: {edition.group()} → "
                      f"{', '.join(g.gr_mem) if g and g.gr_mem else '(sin miembros)'}")
        console.print(f"Tú ({system.operator()}): " + ("[green]con acceso[/]" if ok else f"[yellow]{escape(why)}[/]"))
        console.print(f"Dar acceso a alguien: {NAME} usuarios grupo_add <usuario> --grupo {edition.group()}")
    else:
        console.print("Incluye la administración diaria y análisis básico. Para la completa: "
                      "sudo ./install.sh --edicion completa")
    return 0


def cmd_instalar_todo(yes: bool, opcionales: bool = False) -> int:
    mods = [m for m in all_modules() if installer.wanted_packages(m, opcionales)]
    if not mods:
        console.print("[green]No falta nada por instalar en esta edición.[/]")
        return 0
    pm = packages.manager()
    pkgs = pm.missing([p for m in mods for p in installer.wanted_packages(m, opcionales)])
    console.print("Módulos a completar: " + ", ".join(m.name for m in mods))
    pm.refresh(lambda l: console.print(l, markup=False, style="dim"))
    plan = pm.plan(pkgs)
    console.print("\n" + plan.summary(), markup=False)
    if plan.error or not plan.to_install:
        return 1 if plan.error else 0
    if not yes and not _ask_yes("¿Desea continuar?"):
        console.print("Cancelado.")
        return 1
    wanted = [p for p in plan.requested if p not in plan.unavailable]
    rc = pm.install(wanted, lambda l: console.print(l, markup=False))
    audit.record("instalar_dependencias", "todo", "OK" if rc == 0 else f"ERROR_{rc}", " ".join(wanted))
    return 0 if rc == 0 else 1


def cmd_instalar(args: list[str], yes: bool, opcionales: bool = False) -> int:
    if not args:
        console.print(f"Uso: {NAME} instalar <módulo|todo> [--opcionales]")
        return 1
    if args[0] == "todo":
        return cmd_instalar_todo(yes, opcionales)
    m = module(args[0])
    if not m:
        console.print(f"[red]No existe el módulo '{escape(args[0])}'[/]")
        return 1
    st = m.status()
    if st.state == AVAILABLE and not installer.wanted_packages(m, opcionales):
        console.print(f"[green]{m.name} ya tiene todo lo necesario.[/]")
        falta = [r.describe() for r in m.missing_optional()]
        if falta and not opcionales:
            console.print(f"Herramientas opcionales que puedes añadir: {', '.join(falta)}  →  "
                          f"{NAME} instalar {m.id} --opcionales")
        return 0
    if st.state not in (AVAILABLE, INSTALLABLE):
        console.print(f"[red]{m.name}: {escape(st.reason)}[/]")
        return 1
    plan = installer.prepare(m, lambda l: console.print(l, markup=False, style="dim"), opcionales)
    console.print("\n" + plan.summary(), markup=False)
    if plan.error or not plan.to_install:
        return 1 if plan.error else 0
    if not yes and not _ask_yes("¿Desea continuar?"):
        console.print("Cancelado.")
        return 1
    ok = installer.install(m, plan, lambda l: console.print(l, markup=False))
    console.print(f"[green]{m.name} listo.[/]" if ok else "[red]La instalación no se completó.[/]")
    return 0 if ok else 1


def cmd_registro(args: list[str]) -> int:
    n = int(args[0]) if args and args[0].isdigit() else 50
    text = next((a for a in args if not a.isdigit()), "")
    rows = audit.read(n, text)
    if not rows:
        console.print("No hay registros" + (f" con '{text}'" if text else "") + f" en {paths.AUDIT_LOG}")
        return 0
    t = Table("Fecha", "Operador", "Acción", "Objetivo", "Resultado", "Detalle", show_edge=False, header_style="bold")
    for r in rows:
        t.add_row(*[Text(str(r.get(k, ""))) for k in ("fecha", "operador", "accion", "objetivo", "resultado",
                                                          "detalle")])
    console.print(t)
    return 0


def cmd_resultados(args: list[str]) -> int:
    from .core import results
    rows = [(m, d) for m, d in results.all_sessions(100) if not args or m == args[0]]
    if not rows:
        console.print("No hay resultados guardados" + (f" de '{args[0]}'" if args else "") + ".")
        return 0
    t = Table("Módulo", "Fecha", "Carpeta", show_edge=False, header_style="bold")
    for m, d in rows[:50]:
        n = d.name
        t.add_row(m, f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}", str(d))
    console.print(t)
    return 0


def cmd_autoactualizar(yes: bool) -> int:
    from .core import actualizar
    est = actualizar.comprobar(VERSION)
    if est.estado == actualizar.AL_DIA:
        console.print(f"[green]{NAME} {VERSION} ya es la última versión.[/]")
        return 0
    if not est.hay_nueva:
        console.print(escape(est.mensaje))
        return 1
    console.print(f"Hay una versión nueva de {NAME}.\n  Versión actual: {VERSION}\n  Versión nueva:  "
                  + escape(est.nueva_texto))
    if not yes and not _ask_yes("¿Actualizar ahora?"):
        console.print("Cancelado.")
        return 1
    res = actualizar.instalar(est)
    if not res.ok:
        console.print(escape(res.mensaje))
        return 1
    console.print(f"[green]{NAME} actualizado a la versión {escape(res.nueva or 'nueva')}.[/]")
    if res.instalador_cambiado:
        console.print(f"[yellow]El instalador ha cambiado: ejecuta {escape(str(paths.APP_DIR / 'install.sh'))} "
                      "para aplicar los cambios del lanzador y de los permisos.[/]")
    return 0


def _read_secret(label: str) -> "str | None":
    """Pide un secreto sin eco (o lo lee de la entrada estándar si no es un terminal)."""
    try:
        if sys.stdin.isatty():
            return getpass.getpass(f"{label}: ")
        return sys.stdin.readline().rstrip("\n")
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def cmd_accion(m, a, values: dict, yes: bool) -> int:
    pos = values.pop("_pos", [])
    for p in a.visible_params():                       # el primer dato se puede dar sin --nombre
        if p.name not in values and pos and not p.advanced:
            values[p.name] = pos.pop(0)
        if p.kind == "password" and p.name in values:
            if values[p.name] == "-":
                secret = _read_secret(p.label)
                if secret is None:
                    return 1
                values[p.name] = secret
            elif values[p.name]:
                console.print(f"[yellow]Aviso: --{p.name} en la línea de comandos queda en el historial y en el "
                              f"registro de sudo. Usa --{p.name} - para escribirlo sin que se vea.[/]")
        if p.name in values or p.kind == "bool":
            if p.kind == "bool" and p.name in values and isinstance(values[p.name], str):
                values[p.name] = values[p.name].lower() in ("1", "si", "sí", "true", "yes", "s")
            continue
        if not p.required or p.advanced:
            continue
        if p.default not in ("", None):
            values[p.name] = p.default
            continue
        if not sys.stdin.isatty():
            console.print(f"[red]Falta --{p.name} ({p.label})[/]")
            return 2
        prompt = f"{p.label}" + (f" [{p.default}]" if p.default not in ("", None) else "") + ": "
        try:
            val = getpass.getpass(prompt) if p.kind == "password" else input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        values[p.name] = val or p.default
    text = a.confirm_text({**{p.name: p.default for p in a.params}, **values})
    if text and not yes:
        if not sys.stdin.isatty():
            console.print(f"[yellow]{escape(text)}[/]\nEsta acción pide confirmación: repítela añadiendo --si")
            return 1
        if not _ask_yes(text):
            console.print("Cancelado.")
            return 1
    ok = execute(m, a, values, Context(ConsoleOut(), interactive=sys.stdin.isatty()))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if argv[:1] in (["-v"], ["--version"], ["version"]):
        print(f"{NAME} {VERSION}")
        return 0
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    if not argv:
        if not sys.stdout.isatty():
            print(__doc__)
            return 0
        from .ui.app import run
        return run()
    values, yes = _parse(argv[1:])
    cmd = argv[0]
    if cmd in ("modulos", "módulos", "catalogo", "catálogo"):
        return cmd_modulos()
    if cmd in ("ayuda", "help", "?"):
        return cmd_ayuda(argv[1:])
    if cmd == "instalar":
        return cmd_instalar(values.get("_pos", []), yes, bool(values.get("opcionales")))
    if cmd == "registro":
        return cmd_registro(argv[1:])
    if cmd in ("edicion", "edición"):
        return cmd_edicion()
    if cmd == "resultados":
        return cmd_resultados(argv[1:])
    if cmd in ("autoactualizar", "update"):
        return cmd_autoactualizar(yes)
    m = module(cmd)
    if not m:
        console.print(f"[red]Comando o módulo desconocido: {escape(cmd)}[/]\n")
        print(__doc__)
        return 2
    st = m.status()
    if st.state != AVAILABLE:
        console.print(f"[yellow]{m.name} no está disponible: {escape(st.reason)}[/]" +
                      (f"\nPuedes instalarlo con: {NAME} instalar {m.id}" if st.state == INSTALLABLE else ""))
        return 1
    pos = values.get("_pos", [])
    if not pos:
        return cmd_acciones(m)
    a = m.action(pos[0])
    if not a or not a.available():
        console.print(f"[red]{m.id} no tiene la acción '{escape(pos[0])}'[/]")
        return cmd_acciones(m)
    values["_pos"] = pos[1:]
    if pos[1:2] == ["?"]:
        return cmd_ayuda([m.id, a.id])
    return cmd_accion(m, a, values, yes)
