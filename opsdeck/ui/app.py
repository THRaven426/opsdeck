"""Interfaz visual (Textual). Funciona en cualquier terminal, también por SSH o dentro
de una sesión de escritorio remoto, con teclado o ratón.

Pantallas: Inicio (estado del equipo, de la herramienta, del alcance y de las fuentes), módulo
(acciones, vista previa de la acción, y pestañas Salida / Resultados / Ayuda), búsqueda rápida (/),
Resultados (g), Catálogo (c), Registro (l) y Actualizar opsdeck (u).

Teclas: / buscar · ? ayuda · u actualizar · g resultados · c catálogo · r volver a detectar ·
l registro · t tema · s detener · q salir · Esc volver."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unicodedata
from typing import Optional

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.suggester import SuggestFromList
from textual.theme import Theme
from textual.widgets import (Button, Checkbox, ContentSwitcher, DataTable, Footer, Header, Input, Label,
                             Markdown, OptionList, ProgressBar, RichLog, Select, Static, TabbedContent, TabPane)
from textual.widgets.option_list import Option

from .. import NAME, VERSION
from ..core import accounts, actualizar, audit, config, edition, feeds, installer, paths, results, scope, system
from ..core.catalog import AVAILABLE, CATEGORIES, INSTALLABLE, Action, Context, Module, all_modules
from ..core.ops import check_params, execute

WELCOME = f"""\
# Bienvenido a {NAME}

1. Elige un **módulo** en la columna de la izquierda (o pulsa **/** y escribe lo que buscas).
2. Elige una **acción** y pulsa Intro (o haz clic). A la derecha ves qué hace y qué datos pide.
3. Si la acción necesita datos, se abre un formulario. Las que cambian algo piden confirmación.

En cualquier momento pulsa **?** para ver la ayuda de lo que tengas seleccionado.
Pulsa **c** para ver el catálogo completo: módulos disponibles, los que se pueden instalar
y los que no aplican a este equipo.
"""

CAT_STYLE = {"Sistemas": "bold #5fafff", "Blue team": "bold #5fd7af", "Ciberseguridad": "bold #ffaf5f"}
CAT_ICON = {"Sistemas": "▣", "Blue team": "◈", "Ciberseguridad": "◎"}

# Colores de palabras de estado en las tablas (siempre acompañan al texto: no dependen solo del color)
STATE_STYLES = {
    "CONFIRMADA": "bold red", "NO APLICA": "green", "NO REPRODUCIDA": "green", "NO CONCLUYENTE": "yellow",
    "CRÍTICO": "bold red", "ALTO": "red", "MEDIO": "yellow", "BAJO": "cyan", "INFO": "dim",
    "critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan",
    "SIGUE": "bold red", "NO REPRODUCIDO": "green", "NO ACCESIBLE": "yellow",
}

THEMES = {
    "opsdeck": Theme(name="opsdeck", primary="#3a8fd6", secondary="#5fd7af", accent="#ffaf5f", warning="#e5c07b",
                     error="#ef5f5f", success="#5fd787", foreground="#d8dee9", background="#11151c",
                     surface="#171c25", panel="#1f2632", dark=True),
    "claro": Theme(name="opsdeck-claro", primary="#005fa3", secondary="#00875f", accent="#b35900",
                   warning="#8a6d00", error="#c0262d", success="#1a7f37", foreground="#1b1f24",
                   background="#f6f8fa", surface="#ffffff", panel="#e8ecf0", dark=False),
    "contraste": Theme(name="opsdeck-contraste", primary="#00d7ff", secondary="#00ff87", accent="#ffff00",
                       warning="#ffff00", error="#ff5f5f", success="#00ff87", foreground="#ffffff",
                       background="#000000", surface="#000000", panel="#1c1c1c", dark=True),
}
THEME_LABEL = {"opsdeck": "oscuro", "claro": "claro", "contraste": "alto contraste"}


def _fold(s: str) -> str:
    """Texto en minúsculas y sin tildes, para buscar «verificacion» y encontrar «Verificación»."""
    return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")


def _session_label(name: str) -> str:
    return f"{name[:4]}-{name[4:6]}-{name[6:8]} {name[9:11]}:{name[11:13]}"


# ---------------------------------------------------------------- salida en pantalla

class TuiOut:
    """Escribe en el panel de salida desde el hilo de la acción."""

    def __init__(self, app: "OpsdeckApp", log: RichLog):
        self.app, self.log = app, log

    def _w(self, renderable) -> None:
        self.app.call_from_thread(self._write, renderable)

    def _write(self, renderable) -> None:
        # Se pasa el ancho real del panel: si no, RichLog mide con el ancho de la consola interna
        # (80 columnas en algunos terminales) y las tablas y líneas largas se cortan a media pantalla.
        w = self.log.scrollable_content_region.width
        self.log.write(renderable, width=w if w >= 40 else None)

    def info(self, m): self._w(Text.assemble(("[*] ", "bold blue"), m))
    def ok(self, m): self._w(Text.assemble(("[+] ", "bold green"), m))
    def warn(self, m): self._w(Text.assemble(("[!] ", "bold yellow"), m))
    def error(self, m): self._w(Text.assemble(("[-] ", "bold red"), m))
    def line(self, m=""): self._w(Text(m))
    def title(self, m): self._w(Text("\n" + m, style="bold underline"))

    def table(self, headers, rows):
        t = Table(*headers, show_edge=False, header_style="bold", expand=False, row_styles=["", "dim"]
                  if len(rows) > 6 else None)
        for r in rows:
            t.add_row(*[Text(str(c), style=STATE_STYLES.get(str(c), "")) for c in r])
        self._w(t)

    def secret(self, label, value):
        self._w(Text.assemble("\n  ", (f"{label}: ", "bold yellow"), (f" {value} ", "bold reverse"), "\n"))

    def check(self, good, m):
        self._w(Text.assemble(("  ✓ " if good else "  ✗ ", "bold green" if good else "bold red"), m))


# ---------------------------------------------------------------- ventanas

class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,q,question_mark", "close", "Cerrar")]

    def __init__(self, markdown: str):
        super().__init__()
        self.markdown = markdown

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            with VerticalScroll(id="help-doc"):
                yield Markdown(self.markdown)
            with Horizontal(classes="buttons"):
                yield Button("Cerrar (Esc)", variant="primary", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "no", "Cancelar")]

    def __init__(self, text: str, yes: str = "Sí, continuar", danger: bool = True):
        super().__init__()
        self.text, self.yes, self.danger = text, yes, danger

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog" + (" danger" if self.danger else "")):
            yield Static("⚠  Confirmación" if self.danger else "Confirmación", classes="dialog-title")
            yield Static(self.text, markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Cancelar (Esc)", id="no")
                yield Button(self.yes, variant="error" if self.danger else "primary", id="yes")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_no(self) -> None:
        self.dismiss(False)


class FormCheckbox(Checkbox):
    """Casilla que se marca con espacio o clic; Intro acepta el formulario."""
    BINDINGS = [Binding("space", "toggle_button", "Marcar", show=False)]


class FormScreen(ModalScreen[Optional[dict]]):
    BINDINGS = [Binding("escape", "cancel", "Cancelar"), Binding("f1", "help", "Ayuda"),
                Binding("enter", "submit", "Aceptar", show=False)]

    def __init__(self, module: Module, action: Action, initial: Optional[dict] = None):
        super().__init__()
        self.module, self.action_def = module, action
        self.params = action.visible_params()
        self.initial = initial or {}

    def _default(self, p):
        return self.initial.get(p.name, p.default)

    def compose(self) -> ComposeResult:
        basic = [p for p in self.params if not p.advanced]
        adv = [p for p in self.params if p.advanced]
        with Vertical(classes="dialog"):
            yield Static(f"{self.module.name} › {self.action_def.label}", classes="dialog-title")
            if self.action_def.help:
                yield Static(self.action_def.help, classes="hint")
            yield Static("Intro = aceptar · Esc = cancelar · F1 = ayuda · Espacio = marcar casillas", classes="hint keys")
            with VerticalScroll(id="form-fields"):
                for p in basic:
                    yield from self._field(p)
                if adv:
                    yield FormCheckbox(f"Mostrar opciones avanzadas ({len(adv)})",
                                       any(p.name in self.initial for p in adv), id="adv-toggle")
                    with Vertical(id="adv-box"):
                        yield Static("Opciones avanzadas: déjalas como están si no sabes qué hacen; "
                                     "los valores por defecto son los recomendados.", classes="hint")
                        for p in adv:
                            yield from self._field(p)
            yield Static("", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancelar", id="cancel")
                yield Button("Aceptar", variant="primary", id="ok")

    def _field(self, p) -> ComposeResult:
        wid = f"f-{p.name}"
        optional = "" if (p.required and p.kind != "bool") or p.advanced else "  (opcional)"
        value = self._default(p)
        if p.kind == "bool":
            yield FormCheckbox(p.label, bool(value), id=wid)
        else:
            yield Label(p.label + optional, classes="field-label")
            if p.kind == "choice":
                valid = [val for val, _ in p.choices]
                yield Select([(text, val) for val, text in p.choices], value=value if value in valid else p.choices[0][0],
                             allow_blank=False, id=wid)
            elif p.kind in ("user", "group"):
                names = accounts.human_names() if p.kind == "user" else \
                    [g.gr_name for g in accounts.local_groups()]
                yield Input(str(value or ""), id=wid, suggester=SuggestFromList(names),
                            placeholder="Empieza a escribir; → acepta la sugerencia")
                if p.kind == "user" and len(names) <= 25:
                    p_help = "Usuarios: " + ", ".join(names)
                    yield Static(p_help + (("\n" + p.help) if p.help else ""), classes="hint")
                    return
            else:
                sug = None
                if p.suggest:
                    try:
                        sug = SuggestFromList(p.suggest(), case_sensitive=False)
                    except Exception:
                        sug = None
                yield Input(str(value if value is not None else ""), id=wid, password=p.kind == "password",
                            type="integer" if p.kind == "int" else "text", suggester=sug,
                            placeholder="Empieza a escribir; → acepta la sugerencia" if sug else "")
        if p.help:
            yield Static(p.help, classes="hint")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "adv-toggle":
            box = self.query_one("#adv-box")
            box.display = bool(event.value)
            if event.value:
                first = next((p for p in self.params if p.advanced), None)
                if first:
                    self.query_one(f"#f-{first.name}").focus()
                    box.scroll_visible()

    def on_mount(self) -> None:
        if any(p.advanced for p in self.params):
            self.query_one("#adv-box").display = any(p.name in self.initial for p in self.params if p.advanced)
        first = next((p for p in self.params if not p.advanced), None) or (self.params[0] if self.params else None)
        if first and not first.advanced:
            self.query_one(f"#f-{first.name}").focus()
        elif first:
            self.query_one("#adv-toggle").focus()

    def values(self) -> dict:
        out = {}
        for p in self.params:
            w = self.query_one(f"#f-{p.name}")
            out[p.name] = w.value
        return out

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.submit()

    def submit(self) -> None:
        vals = self.values()
        problem = check_params(self.action_def, dict(vals))
        if problem:
            self.query_one("#error", Static).update("✗ " + problem)
            return
        self.dismiss(vals)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_submit(self) -> None:
        self.submit()

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen(action_help(self.module, self.action_def)))


def action_help(module: Module, action: Action) -> str:
    lines = [f"# {module.name} › {action.label}", "", action.help or "", ""]
    params = action.visible_params()
    for title, group in (("## Datos que pide", [p for p in params if not p.advanced]),
                         ("## Opciones avanzadas (opcionales)", [p for p in params if p.advanced])):
        if not group:
            continue
        lines += [title, ""]
        for p in group:
            opt = "" if p.required and p.kind != "bool" else " *(opcional)*"
            lines.append(f"- **{p.label}** (`--{p.name}`){opt}" + (f": {p.help}" if p.help else ""))
            for val, text in p.choices:
                lines.append(f"  - `{val}`: {text}")
        lines.append("")
    if action.changes:
        lines += ["> Esta acción **cambia el sistema**. Queda registrada y antes se guarda una copia "
                  "de las cuentas del sistema.", ""]
    req = [p.name for p in params if p.required and p.kind != "bool"]
    lines += ["## Desde la línea de comandos", "",
              f"`{NAME} {module.id} {action.id} " + " ".join(f"--{n} ..." for n in req) + "`", "",
              "---", "", module.help]
    return "\n".join(lines)


def action_preview(module: Module, action: Action) -> str:
    """Resumen corto de la acción para el panel lateral del módulo."""
    lines = [f"### {action.label}", ""]
    if action.help:
        lines += [action.help, ""]
    params = action.visible_params()
    basic = [p.label + ("" if p.required else " (opcional)") for p in params if not p.advanced and p.kind != "bool"]
    adv = [p for p in params if p.advanced]
    lines.append("**Pide:** " + (", ".join(basic) if basic else "nada, se ejecuta directamente"))
    if adv:
        lines.append(f"  \n**Opciones avanzadas:** {len(adv)} (opcionales)")
    lines.append("")
    if action.changes:
        lines += ["> ● **Cambia el sistema**: pide confirmación y queda en el registro.", ""]
    elif action.confirm:
        lines += ["> Pide confirmación antes de lanzarse.", ""]
    req = [p.name for p in params if p.required and p.kind != "bool"]
    lines += [f"`{NAME} {module.id} {action.id}" + "".join(f" --{n} …" for n in req) + "`", "",
              "Intro = ejecutar · ? = ayuda completa"]
    return "\n".join(lines)


# ---------------------------------------------------------------- búsqueda rápida

class SearchScreen(ModalScreen[Optional[tuple]]):
    """Buscar cualquier módulo o acción escribiendo parte de su nombre."""
    BINDINGS = [Binding("escape", "cancel", "Cerrar"), Binding("down", "down", show=False),
                Binding("up", "up", show=False)]

    def __init__(self, modules: list[Module]):
        super().__init__()
        self.entries: list[tuple[str, str, Optional[str], str]] = []    # (texto, módulo, acción, buscable)
        for m in modules:
            self.entries.append((m.name, m.id, None, _fold(f"{m.name} {m.summary} {m.category}")))
            for a in m.actions():
                if a.available():
                    self.entries.append((f"{m.name} › {a.label}", m.id, a.id, _fold(f"{m.name} {a.label} {a.help}")))

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog", id="search-dialog"):
            yield Static("Buscar módulo o acción", classes="dialog-title")
            yield Input(placeholder="Escribe: verificar, usuario, escaneo, tls, contraseña…", id="search-input")
            yield OptionList(id="search-results")
            yield Static("↑ ↓ elegir · Intro abrir · Esc cerrar", classes="hint keys")

    def on_mount(self) -> None:
        self.fill("")
        self.query_one("#search-input", Input).focus()

    def fill(self, text: str) -> None:
        words = _fold(text).split()
        ol = self.query_one("#search-results", OptionList)
        ol.clear_options()
        self.shown = [e for e in self.entries if all(w in e[3] for w in words)][:200]
        for i, (label, _, act, _) in enumerate(self.shown):
            ol.add_option(Option(Text.assemble(("  ›  " if act else "▸ ", "dim"), (label, "" if act else "bold")), id=str(i)))
        if self.shown:
            ol.highlighted = 0

    @on(Input.Changed, "#search-input")
    def changed(self, event: Input.Changed) -> None:
        self.fill(event.value)

    @on(Input.Submitted, "#search-input")
    def submitted(self, event: Input.Submitted) -> None:
        ol = self.query_one("#search-results", OptionList)
        if self.shown and ol.highlighted is not None:
            self.pick(ol.highlighted)

    @on(OptionList.OptionSelected, "#search-results")
    def selected(self, event: OptionList.OptionSelected) -> None:
        self.pick(int(event.option_id or 0))

    def pick(self, i: int) -> None:
        _, mid, aid, _ = self.shown[i]
        self.dismiss((mid, aid))

    def action_down(self) -> None:
        ol = self.query_one("#search-results", OptionList)
        if ol.option_count:
            ol.highlighted = min((ol.highlighted or 0) + 1, ol.option_count - 1)

    def action_up(self) -> None:
        ol = self.query_one("#search-results", OptionList)
        if ol.option_count:
            ol.highlighted = max((ol.highlighted or 0) - 1, 0)

    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- actualizar la herramienta

class UpdateScreen(ModalScreen[Optional[str]]):
    """Versión nueva: cambios (informativos) → instalar con progreso → reinicio."""
    BINDINGS = [Binding("escape", "close", "Cerrar")]

    def __init__(self, estado: Optional[actualizar.Estado]):
        super().__init__()
        self.estado = estado
        self.busy = False
        self.done: Optional[actualizar.Resultado] = None

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide", id="update-dialog"):
            yield Static(f"Actualizar {NAME}", classes="dialog-title")
            yield Static("", id="upd-versions")
            with VerticalScroll(id="upd-changes"):
                yield Markdown("", id="upd-md", open_links=False)
            yield ProgressBar(total=4, show_eta=False, id="upd-progress")
            yield RichLog(id="upd-log", wrap=True, markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Cerrar (Esc)", id="upd-close")
                yield Button("Comprobar de nuevo", id="upd-check")
                yield Button("Instalar la versión nueva", variant="primary", id="upd-install")
                yield Button("Reiniciar ahora", variant="success", id="upd-restart")

    def on_mount(self) -> None:
        self.query_one("#upd-progress").display = False
        self.query_one("#upd-log").display = False
        self.query_one("#upd-restart").display = False
        self.show_state()
        if self.estado is None:
            self.check()

    def show_state(self) -> None:
        est = self.estado
        vers = self.query_one("#upd-versions", Static)
        md = self.query_one("#upd-md", Markdown)
        inst = self.query_one("#upd-install", Button)
        if est is None:
            vers.update(Text("Comprobando si hay una versión nueva…", style="bold"))
            md.update("")
            inst.display = False
            return
        if est.hay_nueva:
            vers.update(Text.assemble(("Versión instalada: ", "bold"), VERSION, "     ",
                                      ("Versión nueva: ", "bold"), (est.nueva_texto, "bold green")))
            md.update("## Cambios de la versión nueva\n\n*Solo informativo: es el registro de cambios publicado "
                      "en el repositorio.*\n\n" + (est.cambios or "_El repositorio no incluye un registro de cambios._"))
            inst.display = system.is_root()
            if not system.is_root():
                md.update("> Para instalar abre la herramienta escribiendo solo `opsdeck` (se relanza con sudo).\n\n"
                          + (est.cambios or ""))
        else:
            style = "bold green" if est.estado == actualizar.AL_DIA else "bold yellow"
            vers.update(Text(("✓ " if est.estado == actualizar.AL_DIA else "⚠ ") + est.mensaje, style=style))
            md.update("")
            inst.display = False

    @work(thread=True, exclusive=True, group="update")
    def check(self) -> None:
        est = self.app.check_update_now()
        self.app.call_from_thread(self._checked, est)

    def _checked(self, est) -> None:
        self.estado = est
        self.show_state()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "upd-close":
            self.action_close()
        elif bid == "upd-check" and not self.busy:
            self.estado = None
            self.show_state()
            self.check()
        elif bid == "upd-install" and not self.busy:
            if self.app.running:
                self.app.notify("Espera a que termine la acción en curso.", severity="warning")
                return
            self.install()
        elif bid == "upd-restart":
            self.dismiss("reiniciar")

    def install(self) -> None:
        self.busy = True
        for bid in ("#upd-install", "#upd-check", "#upd-close"):
            self.query_one(bid).disabled = True
        self.query_one("#upd-changes").display = False
        self.query_one("#upd-progress").display = True
        self.query_one("#upd-log").display = True
        self._install()

    @work(thread=True, exclusive=True, group="update")
    def _install(self) -> None:
        log = self.query_one("#upd-log", RichLog)
        bar = self.query_one("#upd-progress", ProgressBar)

        def say(line: str) -> None:
            self.app.call_from_thread(log.write, Text("  " + line))
            self.app.call_from_thread(bar.advance, 1)

        say(f"Instalando {self.estado.nueva_texto}…")
        res = actualizar.instalar(self.estado, say)
        self.app.call_from_thread(self._installed, res)

    def _installed(self, res: actualizar.Resultado) -> None:
        self.busy = False
        self.done = res
        bar = self.query_one("#upd-progress", ProgressBar)
        log = self.query_one("#upd-log", RichLog)
        self.query_one("#upd-close").disabled = False
        if res.ok:
            bar.update(progress=4)
            log.write(Text("✓ " + res.mensaje, style="bold green"))
            if res.instalador_cambiado:
                log.write(Text("El instalador ha cambiado: al reiniciar se aplica antes (install.sh --si).",
                               style="yellow"))
            log.write(Text("Hay que reiniciar opsdeck para usar la versión nueva.", style="bold"))
            self.query_one("#upd-versions", Static).update(Text("✓ Actualización instalada: reinicio necesario",
                                                                style="bold green"))
            self.query_one("#upd-restart").display = True
            self.query_one("#upd-restart").focus()
            self.app.update_installed(res)
        else:
            log.write(Text("✗ " + res.mensaje, style="bold red"))
            self.query_one("#upd-versions", Static).update(Text("✗ No se ha actualizado", style="bold red"))

    def action_close(self) -> None:
        if not self.busy:
            self.dismiss(None)


# ---------------------------------------------------------------- catálogo

class CatalogScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Volver"), Binding("r", "rescan", "Volver a detectar"),
                Binding("i", "install", "Instalar lo que falta"), Binding("o", "install_optional", "Instalar opcionales"),
                Binding("v", "toggle", "Mostrar/ocultar"),
                Binding("question_mark", "help", "Ayuda")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Catálogo de módulos: estado en este equipo. Selecciona uno y usa los botones.",
                     id="screen-summary")
        yield DataTable(id="catalog-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(id="catalog-buttons"):
            yield Button("Instalar lo que falta (i)", id="install", variant="primary")
            yield Button("Herramientas opcionales (o)", id="install_optional")
            yield Button("Mostrar / ocultar en el menú (v)", id="toggle")
            yield Button("Volver a detectar (r)", id="rescan")
            yield Button("Volver (Esc)", id="back")
        yield RichLog(id="catalog-log", wrap=True, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_table()

    def refresh_table(self) -> None:
        t = self.query_one(DataTable)
        t.clear(columns=True)
        t.add_columns("Módulo", "Categoría", "Estado", "En el menú", "Detalle")
        hidden = config.hidden_modules()
        self.mods = all_modules()
        for m in self.mods:
            st = m.status()
            style = {AVAILABLE: "green", INSTALLABLE: "yellow"}.get(st.state, "red")
            state = Text({AVAILABLE: "✓ disponible", INSTALLABLE: "⬇ se puede instalar"}.get(st.state, "— no aplica"),
                         style=style)
            detail = st.reason or m.summary
            if st.state == INSTALLABLE:
                detail += "  ·  paquetes: " + " ".join(st.packages)
            opt = m.missing_optional() if st.state == AVAILABLE else []
            if opt:
                detail += f"  ·  +{len(opt)} opcionales (o): " + ", ".join(r.describe() for r in opt)
            t.add_row(m.name, Text(m.category, style=CAT_STYLE.get(m.category, "")), state,
                      "no" if m.id in hidden else "sí", detail, key=m.id)

    def selected(self) -> Optional[Module]:
        t = self.query_one(DataTable)
        if t.row_count == 0:
            return None
        key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        return next((m for m in self.mods if m.id == key), None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        getattr(self, f"action_{event.button.id}")()

    def action_back(self) -> None:
        self.app.pop_screen()
        self.app.reload_modules()

    def action_rescan(self) -> None:
        self.refresh_table()
        self.query_one(RichLog).write("Detección actualizada.")

    def action_toggle(self) -> None:
        m = self.selected()
        if not m:
            return
        hide = m.id not in config.hidden_modules()
        try:
            config.set_hidden(m.id, hide)
            self.query_one(RichLog).write(f"{m.name}: {'oculto' if hide else 'visible'} en el menú.")
        except OSError as e:
            self.query_one(RichLog).write(f"No se pudo guardar la configuración: {e}")
        self.refresh_table()

    def action_help(self) -> None:
        m = self.selected()
        self.app.push_screen(HelpScreen(m.help if m else WELCOME))

    def action_install_optional(self) -> None:
        m = self.selected()
        if not m:
            return
        log = self.query_one(RichLog)
        if not installer.wanted_packages(m, opcionales=True):
            log.write(f"{m.name}: no hay herramientas opcionales que instalar en este equipo.")
            return
        if not system.is_root():
            log.write("Para instalar paquetes abre la herramienta con sudo.")
            return
        self.prepare_install(m, True)

    def action_install(self) -> None:
        m = self.selected()
        if not m:
            return
        st = m.status()
        log = self.query_one(RichLog)
        if st.state == AVAILABLE:
            log.write(f"{m.name} ya tiene todo lo necesario."
                      + (" Tiene herramientas opcionales: pulsa o." if m.missing_optional() else ""))
            return
        if st.state != INSTALLABLE:
            log.write(f"{m.name} no se puede instalar en este equipo: {st.reason}")
            return
        if not system.is_root():
            log.write("Para instalar paquetes abre la herramienta con sudo.")
            return
        self.prepare_install(m)

    @work(thread=True, exclusive=True, group="install")
    def prepare_install(self, m: Module, opcionales: bool = False) -> None:
        log = self.query_one(RichLog)
        say = lambda l: self.app.call_from_thread(log.write, l)
        say(f"Preparando la instalación de {m.name}" + (" (herramientas opcionales)" if opcionales else "") + "...")
        plan = installer.prepare(m, say, opcionales)
        say(plan.summary())
        if plan.error or not plan.to_install:
            return

        def answer(yes: Optional[bool]) -> None:
            if yes:
                self.do_install(m, plan)
            else:
                log.write("Cancelado: no se ha instalado nada.")

        self.app.call_from_thread(self.app.push_screen,
                                  ConfirmScreen(plan.summary() + "\n\n¿Desea continuar?", "Instalar", danger=False),
                                  answer)

    @work(thread=True, exclusive=True, group="install")
    def do_install(self, m: Module, plan) -> None:
        log = self.query_one(RichLog)
        say = lambda l: self.app.call_from_thread(log.write, l)
        ok = installer.install(m, plan, say)
        say(f"{m.name} listo: ya aparece en el menú." if ok else "La instalación no se completó. Revisa los mensajes.")
        self.app.call_from_thread(self.refresh_table)


# ---------------------------------------------------------------- resultados

VERIFICABLES = ("nuclei", "escaneo", "informes")


class ResultsScreen(Screen):
    """Resultados guardados de todos los módulos: escaneos, análisis, informes y evidencias."""
    BINDINGS = [Binding("escape", "back", "Volver"), Binding("question_mark", "help", "Ayuda"),
                Binding("v", "verify", "Verificar hallazgos")]
    TEXT_EXT = (".txt", ".nmap", ".log", ".json", ".jsonl", ".csv", ".dat", ".sha256", ".gnmap", ".md")

    def __init__(self, module_id: str = "", session: str = ""):
        super().__init__()
        self.filter_module, self.initial = module_id, session
        self.current: Optional[tuple] = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Resultados guardados (más recientes primero). Intro abre; Esc vuelve.", id="screen-summary")
        with Horizontal(id="body"):
            with Vertical(id="res-sidebar"):
                yield DataTable(id="res-sessions", cursor_type="row", zebra_stripes=True)
            with Vertical(id="res-main"):
                with Horizontal(id="res-actions"):
                    yield Static("", id="res-path")
                    yield Button("Verificar hallazgos (v)", id="res-verify", variant="primary")
                yield OptionList(id="res-files")
                yield RichLog(id="res-view", wrap=False, markup=False, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one("#res-sessions", DataTable)
        t.add_columns("Módulo", "Fecha", "Qué")
        self.sessions = [(m, d) for m, d in results.all_sessions(300) if not self.filter_module or m == self.filter_module]
        sel = 0
        for i, (mod, d) in enumerate(self.sessions):
            n = d.name
            t.add_row(mod, _session_label(n), n[16:][:28], key=str(i))
            if self.initial and n == self.initial:
                sel = i
        self.query_one("#res-verify").display = False
        if not self.sessions:
            self.query_one("#res-view", RichLog).write("Todavía no hay resultados guardados.")
        else:
            t.move_cursor(row=sel)
        t.focus()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        mod, d = self.sessions[int(event.row_key.value)]
        self.current = (mod, d)
        files = sorted(p for p in d.rglob("*") if p.is_file())
        ol = self.query_one("#res-files", OptionList)
        ol.clear_options()
        self.files = files
        for i, f in enumerate(files):
            ol.add_option(Option(f"{f.relative_to(d)}  ({max(1, f.stat().st_size // 1024)} KB)", id=str(i)))
        ol.styles.max_height = min(10, max(3, len(files) + 2))
        self.query_one("#res-path", Static).update(Text(str(d), style="dim"))
        self.query_one("#res-verify").display = self.can_verify()
        log = self.query_one("#res-view", RichLog)
        log.clear()
        log.write(f"{d}")

    def can_verify(self) -> bool:
        if not self.current or self.current[0] not in VERIFICABLES:
            return False
        m = next((x for x in self.app.modules if x.id == "verificacion"), None)
        return m is not None

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ol = self.query_one("#res-files", OptionList)
        if ol.option_count:
            ol.highlighted = 0
            ol.focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_id is not None:
            self.show_file(self.files[int(event.option_id)])

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.show_file(self.files[int(event.option_id)])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "res-verify":
            self.action_verify()

    def action_verify(self) -> None:
        if not self.can_verify():
            self.app.notify("Elige un análisis de nuclei, un escaneo o un informe importado.", severity="warning")
            return
        mod, d = self.current
        self.app.pop_screen()
        self.app.open_action("verificacion", "hallazgos", {"origen": mod, "carpeta": d.name})

    def show_file(self, f) -> None:
        log = self.query_one("#res-view", RichLog)
        log.clear()
        if f.suffix not in self.TEXT_EXT and f.suffix != ".xml":
            log.write(f"{f}\n(fichero binario o comprimido: ábrelo con las herramientas adecuadas)")
            return
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError as e:
            log.write(str(e))
            return
        for line in lines[:3000]:
            log.write(line)
        if len(lines) > 3000:
            log.write(f"... ({len(lines) - 3000} líneas más en {f})")

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen(
            "# Resultados guardados\n\nCada escaneo, análisis, revisión e informe se guarda en "
            f"`{results.ROOT}` (solo root), cada uno en su propia carpeta.\n\n1. Elige una ejecución en la "
            "lista de la izquierda.\n2. Intro y elige un fichero para verlo.\n3. En un análisis de nuclei, un "
            "escaneo o un informe importado, **Verificar hallazgos** (v) comprueba sus CVE con pruebas seguras "
            "(el resultado original no se modifica).\n\nSe conservan los últimos "
            f"{config.settings().getint('resultados', 'conservar_por_modulo', fallback=50)} por módulo "
            "(se cambia en la configuración). Los informes CSV e inventarios están en "
            f"`{paths.REPORT_DIR}` y las copias en `{paths.BACKUP_DIR}`."))


class LogScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,q", "close", "Cerrar")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Static(f"Últimos cambios registrados ({paths.AUDIT_LOG})", classes="dialog-title")
            t = DataTable(zebra_stripes=True)
            yield t
            with Horizontal(classes="buttons"):
                yield Button("Cerrar (Esc)", variant="primary")

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("Fecha", "Operador", "Acción", "Objetivo", "Resultado", "Detalle")
        for r in reversed(audit.read(200)):
            res = str(r.get("resultado", ""))
            t.add_row(Text(r.get("fecha", "")[:19].replace("T", " ")),
                      *[Text(str(r.get(k, ""))) for k in ("operador", "accion", "objetivo")],
                      Text(res, style="green" if res == "OK" else STATE_STYLES.get(res, "yellow")),
                      Text(str(r.get("detalle", ""))))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- pantalla principal

class Card(Static):
    """Tarjeta del panel de inicio (título en el borde)."""

    def __init__(self, title: str, id: str):
        super().__init__("", id=id, classes="card")
        self.border_title = title


class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield from self.app.compose_main()

    def on_mount(self) -> None:
        self.app.main = self
        self.app.main_ready()


class OpsdeckApp(App):
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = False
    TITLE = NAME
    BINDINGS = [
        Binding("escape", "back_to_modules", "Volver", show=False),
        Binding("slash", "search", "Buscar", key_display="/"),
        Binding("question_mark", "help", "Ayuda", key_display="?"),
        Binding("u", "update", "Actualizar"),
        Binding("g", "results", "Resultados"),
        Binding("c", "catalog", "Catálogo"),
        Binding("r", "rescan", "Detectar", show=False),
        Binding("l", "log", "Registro"),
        Binding("t", "theme_next", "Tema"),
        Binding("h", "home", "Inicio", show=False),
        Binding("s", "stop", "Detener"),
        Binding("q", "quit", "Salir"),
    ]
    GLOBAL = ("help", "catalog", "rescan", "log", "quit", "stop", "results", "search", "update", "theme_next", "home")

    def check_action(self, action: str, parameters) -> Optional[bool]:
        # Con una ventana abierta (formulario, confirmación, ayuda) o en el catálogo, las teclas
        # globales no actúan: así 'q' o 'c' nunca cierran ni cambian nada por accidente.
        if action == "back_to_modules":
            return isinstance(self.screen, MainScreen)
        if action in self.GLOBAL and not isinstance(self.screen, MainScreen):
            return False
        if action in self.GLOBAL and self.main and isinstance(self.focused, Input):
            return False                  # escribiendo en un campo, las letras son letras
        if action == "stop":
            return bool(self.running)      # solo aparece mientras algo se ejecuta
        if action in ("catalog", "rescan", "quit", "update") and self.running:
            return False
        return True

    def __init__(self):
        super().__init__()
        self.modules: list[Module] = []
        self.current: Optional[Module] = None
        self.main: Optional[MainScreen] = None
        self.running = False
        self.started = 0.0
        self.running_label = ""
        self.update_state: Optional[actualizar.Estado] = None
        self.update_done: Optional[actualizar.Resultado] = None
        self.restart = False
        for t in THEMES.values():
            self.register_theme(t)
        self.theme_key = config.settings().get("interfaz", "tema", fallback="opsdeck").strip()
        if self.theme_key not in THEMES:
            self.theme_key = "opsdeck"
        self.theme = THEMES[self.theme_key].name

    def on_mount(self) -> None:
        self.push_screen(MainScreen())

    def compose_main(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="update-banner"):
            yield Static("", id="update-text")
            yield Button("Ver cambios y actualizar (u)", id="update-open", variant="success")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static(Text.assemble(("◆ ", "bold"), (NAME, "bold"), (f"  v{VERSION}", "dim")), id="brand")
                yield OptionList(id="modules")
                yield Static("/ buscar · ? ayuda", id="sidebar-hint")
            with ContentSwitcher(initial="home", id="views"):
                with VerticalScroll(id="home"):
                    yield Static("", id="home-title")
                    with Grid(id="cards"):
                        yield Card("Equipo", "card-host")
                        yield Card(NAME, "card-tool")
                        yield Card("Alcance autorizado", "card-scope")
                        yield Card("Fuentes de datos", "card-feeds")
                        yield Card("Módulos", "card-mods")
                        yield Card("Cómo empezar", "card-steps")
                    yield Card("Últimos resultados", "card-results")
                    with Horizontal(id="quick"):
                        yield Button("Buscar  /", id="q-search", variant="primary")
                        yield Button("Verificar un CVE", id="q-verify")
                        yield Button("Escanear la red", id="q-scan")
                        yield Button("Resultados  g", id="q-results")
                        yield Button("Catálogo  c", id="q-catalog")
                        yield Button("Ayuda  ?", id="q-help")
                with Vertical(id="module"):
                    yield Static("", id="mod-title")
                    yield Static("", id="mod-summary")
                    with Horizontal(id="mod-top"):
                        yield OptionList(id="actions")
                        with VerticalScroll(id="action-preview"):
                            yield Markdown("", id="action-md")
                    with TabbedContent(id="tabs", initial="tab-out"):
                        with TabPane("Salida", id="tab-out"):
                            yield RichLog(id="output", wrap=True, markup=False, highlight=False)
                        with TabPane("Resultados del módulo", id="tab-res"):
                            yield DataTable(id="mod-results", cursor_type="row", zebra_stripes=True)
                        with TabPane("Ayuda del módulo", id="tab-help"):
                            with VerticalScroll():
                                yield Markdown("", id="mod-help")
        yield Static("", id="status")
        yield Footer()

    # -------------------------------------------------------- arranque

    def main_ready(self) -> None:
        self.sub_title = (f"{system.hostname()} · {system.os_pretty()} · operador: {system.operator()} · "
                          f"edición {edition.current()}")
        self.main.query_one("#update-banner").display = False
        self.reload_modules()
        out = self.main.query_one("#output", RichLog)
        out.write(Text("Elige una acción y pulsa Intro. Pulsa ? para ver la ayuda de lo que tengas seleccionado.",
                       style="bold"))
        if not system.is_root():
            out.write(Text("Aviso: no eres root. Puedes consultar, pero las acciones que cambian algo fallarán. "
                           f"Cierra y abre la herramienta escribiendo solo: {NAME}", style="yellow"))
        self.refresh_home()
        self.set_interval(1.0, self.tick)
        self.main.query_one("#modules", OptionList).focus()
        if self.check_on_start():
            self.check_update_background()

    def check_on_start(self) -> bool:
        if os.environ.get("OPSDECK_SIN_COMPROBAR_ACTUALIZACION"):
            return False
        return config.settings().getboolean("actualizacion", "comprobar_al_abrir", fallback=True)

    def reload_modules(self) -> None:
        hidden = config.hidden_modules()
        mods = all_modules()
        self.modules = [m for m in mods if m.id not in hidden and m.status().state == AVAILABLE]
        extra = [m for m in mods if m.status().state == INSTALLABLE and m.id not in hidden]
        self.installable = len(extra)
        ol = self.main.query_one("#modules", OptionList)
        ol.clear_options()
        ol.add_option(Option(Text.assemble(("⌂ ", "bold"), ("Inicio", "bold")), id="__inicio__"))
        for cat in CATEGORIES:
            items = [m for m in self.modules if m.category == cat]
            if not items:
                continue
            ol.add_option(Option(Text(f"{CAT_ICON.get(cat, '')} {cat.upper()}", style=CAT_STYLE.get(cat, "bold dim")),
                                 disabled=True))
            for m in items:
                ol.add_option(Option(f"   {m.name}", id=m.id))
        ol.add_option(None)
        label = "⚙ Catálogo"
        if extra:
            label += f"  (+{len(extra)})"
        ol.add_option(Option(label, id="__catalog__"))
        self.set_status()

    def set_status(self, text: str = "") -> None:
        if not self.main:
            return
        if not text:
            text = (f"{len(self.modules)} módulos disponibles · {self.installable} instalables · "
                    "/ buscar · ? ayuda · r volver a detectar")
            if self.update_done is not None:
                text = "⟳ Actualización instalada: reinicia opsdeck para usarla (u)   ·   " + text
        self.main.query_one("#status", Static).update(text)

    def tick(self) -> None:
        if self.running and self.main:
            secs = int(time.monotonic() - self.started)
            spin = "◐◓◑◒"[secs % 4]
            self.main.query_one("#status", Static).update(
                Text.assemble((f" {spin} Ejecutando: ", "bold"), self.running_label,
                              f"  ·  {secs // 60:02d}:{secs % 60:02d}  ·  s = detener"))

    # -------------------------------------------------------- inicio

    def refresh_home(self) -> None:
        if not self.main:
            return
        q = self.main.query_one
        q("#home-title", Static).update(Text.assemble(
            ("Panel de inicio", "bold"), ("   ·   elige un módulo a la izquierda o pulsa / para buscar", "dim")))
        root = system.is_root()
        q("#card-host", Card).update(Text.assemble(
            ("Equipo     ", "dim"), system.hostname(), "\n", ("Sistema    ", "dim"), system.os_pretty(), "\n",
            ("Operador   ", "dim"), system.operator(), "\n", ("Edición    ", "dim"), edition.current(), "\n",
            ("Permisos   ", "dim"), ("root ✓", "green") if root else ("sin root ⚠ (solo consulta)", "yellow")))
        self.refresh_update_card()
        try:
            nets = [str(n) for n in scope.authorized_networks() if not n.is_loopback]
        except Exception:
            nets = []
        solo = config.settings().getboolean("red", "solo_configuradas", fallback=False)
        q("#card-scope", Card).update(Text.assemble(
            *(sum(([("● ", "green"), n, "\n"] for n in nets[:6]), []) or [("Solo este equipo (127.0.0.1)\n", "yellow")]),
            *([(f"… y {len(nets) - 6} más\n", "dim")] if len(nets) > 6 else []),
            ("Solo las configuradas" if solo else "Conectadas + configuradas", "dim"), "\n",
            ("Escaneo de red › Alcance autorizado", "dim italic")))
        parts = []
        for f in feeds.status():
            if not f.presente:
                parts += [("○ ", "dim"), (f.nombre, "dim"), (" (no instalada)\n", "dim")]
            elif f.vieja:
                parts += [("⚠ ", "yellow"), f.nombre, (f" ({f.edad_dias} días)\n", "yellow")]
            elif f.edad_dias is None:
                parts += [("⚠ ", "yellow"), f.nombre, (" (sin descargar)\n", "yellow")]
            else:
                parts += [("✓ ", "green"), f.nombre, (f" ({f.edad_dias} d)\n", "dim")]
        q("#card-feeds", Card).update(Text.assemble(*parts, ("Fuentes de datos › Actualizar", "dim italic")))
        cats = []
        for cat in CATEGORIES:
            n = sum(1 for m in self.modules if m.category == cat)
            cats += [(f"{CAT_ICON.get(cat, '')} {cat:<15}", CAT_STYLE.get(cat, "")), f"{n:>3}\n"]
        q("#card-mods", Card).update(Text.assemble(*cats, (f"{self.installable} se pueden instalar (c)", "dim")))
        rows = []
        for mod, d in results.all_sessions(7):
            rows += [(_session_label(d.name) + "   ", "dim"), (f"{mod:<15}", "bold"), d.name[16:][:60], "\n"]
        q("#card-results", Card).update(Text.assemble(*rows) if rows else Text("Todavía no hay resultados.", style="dim"))
        q("#card-steps", Card).update(Text.assemble(
            ("1 ", "bold"), "Revisa el ", ("alcance autorizado", "bold"), "\n",
            ("2 ", "bold"), ("Escaneo de red", "bold"), " › Escanear\n",
            ("3 ", "bold"), "Revisa servicios, TLS, SSH, web, nuclei\n",
            ("4 ", "bold"), ("Verificar vulnerabilidades", "bold"), " para\n  descartar falsos positivos\n",
            ("Todo queda en Resultados (g)", "dim italic")))
        q("#q-verify").display = any(m.id == "verificacion" for m in self.modules)
        q("#q-scan").display = any(m.id == "escaneo" for m in self.modules)

    def refresh_update_card(self) -> None:
        if not self.main:
            return
        est = self.update_state
        if self.update_done is not None:
            line = [("⟳ Actualizada a ", "bold green"), self.update_done.nueva or "la versión nueva",
                    ("\nReinicio pendiente (u)", "bold yellow")]
        elif est is None:
            line = [("… comprobando actualizaciones", "dim")] if self.check_on_start() else \
                [("Comprobación al abrir desactivada (u)", "dim")]
        elif est.hay_nueva:
            line = [("⬆ Versión nueva: ", "bold green"), est.nueva_texto, ("\nPulsa u para ver los cambios", "green")]
        elif est.estado == actualizar.AL_DIA:
            line = [("✓ Al día", "green")]
        else:
            line = [("⚠ ", "yellow"), (est.mensaje.splitlines()[0][:70], "yellow")]
        self.main.query_one("#card-tool", Card).update(Text.assemble(
            ("Versión    ", "dim"), VERSION, "\n", *line, "\n", ("Tema       ", "dim"),
            THEME_LABEL.get(self.theme_key, self.theme_key), ("  (t)", "dim")))
        banner = self.main.query_one("#update-banner")
        if self.update_done is not None:
            self.main.query_one("#update-text", Static).update(Text.assemble(
                (" ⟳ ", "bold"), f"{NAME} se ha actualizado a {self.update_done.nueva or 'la versión nueva'}. ",
                ("Reinicia para usarla.", "bold")))
            self.main.query_one("#update-open", Button).label = "Reiniciar ahora"
            banner.display = True
        elif est is not None and est.hay_nueva:
            self.main.query_one("#update-text", Static).update(Text.assemble(
                (" ⬆ ", "bold"), f"Hay una versión nueva de {NAME}: ", (est.nueva_texto, "bold"),
                f" (instalada {VERSION})"))
            banner.display = True
        else:
            banner.display = False

    _update_lock = threading.Lock()

    def check_update_now(self) -> actualizar.Estado:
        with self._update_lock:          # la comprobación al abrir y la de la ventana no se pisan
            est = actualizar.comprobar(VERSION, fetch=system.is_root(), timeout=30)
        self.call_from_thread(self._set_update_state, est)
        return est

    @work(thread=True, exclusive=True, group="update-check")
    def check_update_background(self) -> None:
        self.check_update_now()

    def _set_update_state(self, est: actualizar.Estado) -> None:
        self.update_state = est
        self.refresh_update_card()
        if est.hay_nueva and self.update_done is None:
            self.notify(f"Hay una versión nueva de {NAME}: {est.nueva_texto}. Pulsa u para ver los cambios.",
                        title="Actualización disponible", timeout=8)

    def update_installed(self, res: actualizar.Resultado) -> None:
        self.update_done = res
        self.refresh_update_card()
        self.set_status()

    def action_update(self) -> None:
        if self.update_done is not None:
            self.ask_restart()
            return
        self.push_screen(UpdateScreen(self.update_state), self._update_closed)

    def _update_closed(self, result: Optional[str]) -> None:
        if result == "reiniciar":
            self.do_restart()

    def ask_restart(self) -> None:
        self.push_screen(ConfirmScreen(f"{NAME} se ha actualizado. Hay que reiniciar la herramienta para usar la "
                                       "versión nueva. ¿Reiniciar ahora?", "Reiniciar ahora", danger=False),
                         lambda yes: yes and self.do_restart())

    def do_restart(self) -> None:
        if self.running:
            self.notify("Espera a que termine la acción en curso.", severity="warning")
            return
        self.restart = True
        self.exit()

    # -------------------------------------------------------- módulos

    def show_home(self) -> None:
        self.current = None
        self.main.query_one("#views", ContentSwitcher).current = "home"
        self.refresh_home()

    def show_module(self, m: Module) -> None:
        self.current = m
        q = self.main.query_one
        q("#views", ContentSwitcher).current = "module"
        q("#mod-title", Static).update(Text.assemble((f"{CAT_ICON.get(m.category, '')} ", CAT_STYLE.get(m.category, "")),
                                                     (m.name, "bold")))
        q("#mod-summary", Static).update(Text.assemble(m.summary, ("   ·   ? = ayuda", "dim")))
        acts = q("#actions", OptionList)
        acts.clear_options()
        group = None
        for a in m.actions():
            if not a.available():
                continue
            if a.group and a.group != group:
                group = a.group
                acts.add_option(Option(Text(a.group.upper(), style="bold dim"), disabled=True))
            mark = Text(" ●", style="bold yellow") if a.changes else Text("")
            acts.add_option(Option(Text.assemble("  " if a.group else "", a.label, mark), id=a.id))
        first = next((i for i in range(acts.option_count) if not acts.get_option_at_index(i).disabled), None)
        if first is not None:
            acts.highlighted = first
        q("#mod-help", Markdown).update(m.help or m.summary)
        self.fill_module_results(m)

    def fill_module_results(self, m: Module) -> None:
        t = self.main.query_one("#mod-results", DataTable)
        t.clear(columns=True)
        t.add_columns("Fecha", "Qué", "Ficheros")
        self.mod_sessions = results.sessions(m.id, 50)
        for i, d in enumerate(self.mod_sessions):
            try:
                n = sum(1 for p in d.rglob("*") if p.is_file())
            except OSError:
                n = 0
            t.add_row(_session_label(d.name), d.name[16:][:50], str(n), key=str(i))
        self.main.query_one("#tabs", TabbedContent).get_tab("tab-res").label = (
            f"Resultados del módulo ({len(self.mod_sessions)})")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "mod-results" and self.current and event.row_key is not None:
            d = self.mod_sessions[int(event.row_key.value)]
            self.push_screen(ResultsScreen(self.current.id, d.name))

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_list.id == "modules" and event.option_id:
            if event.option_id == "__inicio__":
                if self.current is not None:
                    self.show_home()
                return
            if event.option_id == "__catalog__":
                return
            m = next((x for x in self.modules if x.id == event.option_id), None)
            if m and m is not self.current:
                self.show_module(m)
        elif event.option_list.id == "actions" and self.current and event.option_id:
            a = self.current.action(event.option_id)
            if a:
                self.main.query_one("#action-md", Markdown).update(action_preview(self.current, a))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "modules":
            if event.option_id == "__catalog__":
                self.action_catalog()
                return
            if event.option_id == "__inicio__":
                self.show_home()
                return
            m = next((x for x in self.modules if x.id == event.option_id), None)
            if m:
                self.show_module(m)
                self.main.query_one("#actions", OptionList).focus()
        elif event.option_list.id == "actions" and self.current:
            a = self.current.action(event.option_id or "")
            if a:
                self.start_action(self.current, a)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "update-open":
            self.action_update()
        elif bid == "q-search":
            self.action_search()
        elif bid == "q-verify":
            self.open_action("verificacion", "cve")
        elif bid == "q-scan":
            self.goto_module("escaneo")
        elif bid == "q-results":
            self.action_results()
        elif bid == "q-catalog":
            self.action_catalog()
        elif bid == "q-help":
            self.action_help()

    def goto_module(self, mid: str) -> Optional[Module]:
        m = next((x for x in self.modules if x.id == mid), None)
        if not m:
            self.notify("Ese módulo no está disponible en este equipo (mira el Catálogo).", severity="warning")
            return None
        ol = self.main.query_one("#modules", OptionList)
        for i in range(ol.option_count):
            if ol.get_option_at_index(i).id == mid:
                ol.highlighted = i
                break
        self.show_module(m)
        self.main.query_one("#actions", OptionList).focus()
        return m

    def open_action(self, mid: str, aid: str, initial: Optional[dict] = None) -> None:
        m = self.goto_module(mid)
        if not m:
            return
        a = m.action(aid)
        if not a or not a.available():
            self.notify("Esa acción no está disponible.", severity="warning")
            return
        acts = self.main.query_one("#actions", OptionList)
        for i in range(acts.option_count):
            if acts.get_option_at_index(i).id == aid:
                acts.highlighted = i
                break
        self.start_action(m, a, initial)

    def action_back_to_modules(self) -> None:
        # Esc en la pantalla principal: si el foco está en la lista de acciones, vuelve a la de módulos.
        if not isinstance(self.screen, MainScreen) or not self.main:
            return
        if self.focused is not self.main.query_one("#modules", OptionList):
            self.main.query_one("#modules", OptionList).focus()

    def start_action(self, m: Module, a: Action, initial: Optional[dict] = None) -> None:
        if self.running:
            self.notify("Espera a que termine la acción en curso.", severity="warning")
            return
        if self.update_done is not None:
            self.notify("Se ha instalado una versión nueva: reinicia opsdeck (u) antes de seguir.", severity="warning")
            return
        if a.visible_params():
            self.push_screen(FormScreen(m, a, initial),
                             lambda vals: vals is not None and self.confirm_and_run(m, a, vals))
        else:
            self.confirm_and_run(m, a, {})

    def confirm_and_run(self, m: Module, a: Action, vals: dict) -> None:
        text = a.confirm_text({**{p.name: p.default for p in a.params}, **vals})
        if text:
            self.push_screen(ConfirmScreen(text), lambda yes: yes and self.launch_action(m, a, vals))
        else:
            self.launch_action(m, a, vals)

    def launch_action(self, m: Module, a: Action, vals: dict) -> None:
        self.main.query_one("#tabs", TabbedContent).active = "tab-out"
        out = self.main.query_one("#output", RichLog)
        out.write(Text.assemble("\n", (f" {m.name} › {a.label} ", "bold reverse"), ("  " + time.strftime("%H:%M:%S"), "dim")))
        self.running = True
        self.started = time.monotonic()
        self.running_label = a.label
        self.refresh_bindings()
        self.tick()
        self._worker(m, a, vals)

    @work(thread=True, exclusive=True, group="action")
    def _worker(self, m: Module, a: Action, vals: dict) -> None:
        out = self.main.query_one("#output", RichLog)
        ok = execute(m, a, dict(vals), Context(TuiOut(self, out)))
        self.call_from_thread(self._done, m, a, ok)

    def _done(self, m: Module, a: Action, ok: bool) -> None:
        self.running = False
        self.refresh_bindings()
        secs = int(time.monotonic() - self.started)
        self.set_status(f"{'✓ Terminado' if ok else '✗ Terminado con errores'}: {a.label} "
                        f"({secs // 60:02d}:{secs % 60:02d})   ·   ? = ayuda")
        if not ok:
            self.notify(f"{a.label}: terminó con errores. Revisa la salida.", severity="error", timeout=5)
        if a.changes:
            self.reload_modules()
        if self.current is m:
            self.fill_module_results(m)

    # -------------------------------------------------------- teclas globales

    def action_help(self) -> None:
        focused = self.focused
        acts = self.main.query_one("#actions", OptionList)
        if focused is acts and self.current and acts.highlighted is not None:
            opt = acts.get_option_at_index(acts.highlighted)
            a = self.current.action(opt.id or "")
            if a:
                self.push_screen(HelpScreen(action_help(self.current, a)))
                return
        if self.current and focused in (acts, self.main.query_one("#modules", OptionList)):
            self.push_screen(HelpScreen(self.current.help))
            return
        text = paths.HELP_FILE.read_text(encoding="utf-8") if paths.HELP_FILE.exists() else WELCOME
        self.push_screen(HelpScreen(text))

    def action_search(self) -> None:
        def picked(res: Optional[tuple]) -> None:
            if not res:
                return
            mid, aid = res
            if aid:
                self.open_action(mid, aid)
            else:
                self.goto_module(mid)
        self.push_screen(SearchScreen(self.modules), picked)

    def action_home(self) -> None:
        ol = self.main.query_one("#modules", OptionList)
        ol.highlighted = 0
        self.show_home()
        ol.focus()

    def action_theme_next(self) -> None:
        keys = list(THEMES)
        self.theme_key = keys[(keys.index(self.theme_key) + 1) % len(keys)]
        self.theme = THEMES[self.theme_key].name
        self.refresh_update_card()
        saved = ""
        if system.is_root():
            try:
                config.set_value("interfaz", "tema", self.theme_key)
                saved = " (guardado)"
            except OSError:
                saved = ""
        self.notify(f"Tema: {THEME_LABEL[self.theme_key]}{saved}", timeout=3)

    def action_catalog(self) -> None:
        self.push_screen(CatalogScreen())

    def action_rescan(self) -> None:
        self.reload_modules()
        self.refresh_home()
        self.notify("Detección actualizada: el menú muestra lo que hay ahora en el equipo.")

    def action_log(self) -> None:
        self.push_screen(LogScreen())

    def action_results(self) -> None:
        self.push_screen(ResultsScreen())

    def action_stop(self) -> None:
        if system.stop_current():
            self.notify("Deteniendo...", severity="warning")
        else:
            self.notify("Esta acción no se puede detener a mitad; espera a que termine.")


def _restart(app: OpsdeckApp) -> None:
    """Vuelve a abrir la herramienta con el código nuevo (fuera de la interfaz, en la terminal)."""
    res = app.update_done
    if res is not None and res.instalador_cambiado and system.is_root():
        print("El instalador ha cambiado: aplicándolo (install.sh --si)…", flush=True)
        r = subprocess.run([str(paths.APP_DIR / "install.sh"), "--si"], check=False)
        if r.returncode != 0:
            print(f"install.sh terminó con código {r.returncode}: revísalo y ejecútalo a mano "
                  f"(sudo {paths.APP_DIR / 'install.sh'}).", flush=True)
    print(f"Reiniciando {NAME}…", flush=True)
    argv = actualizar.argv_reinicio()
    os.execv(argv[0], argv)


def run() -> int:
    app = OpsdeckApp()
    app.run()
    if app.restart:
        sys.stdout.flush()
        _restart(app)
    return 0
