"""Interfaz visual (Textual). Funciona en cualquier terminal, también por SSH o dentro
de una sesión de escritorio remoto, con teclado o ratón.

Teclas: ? ayuda de lo que tengas seleccionado · c catálogo · r volver a detectar ·
l registro de cambios · q salir · Esc cerrar ventana."""

from __future__ import annotations

from typing import Optional

from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.suggester import SuggestFromList
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input, Label, Markdown,
                             OptionList, RichLog, Select, Static)
from textual.widgets.option_list import Option

from .. import NAME, VERSION
from ..core import accounts, audit, config, edition, installer, paths, results, system
from ..core.catalog import AVAILABLE, CATEGORIES, INSTALLABLE, Action, Context, Module, all_modules
from ..core.ops import check_params, execute

WELCOME = f"""\
# Bienvenido a {NAME}

1. Elige un **módulo** en la columna de la izquierda.
2. Elige una **acción** y pulsa Intro (o haz clic).
3. Si la acción necesita datos, se abre un formulario. Las que cambian algo piden confirmación.

En cualquier momento pulsa **?** para ver la ayuda de lo que tengas seleccionado.
Pulsa **c** para ver el catálogo completo: módulos disponibles, los que se pueden instalar
y los que no aplican a este equipo.
"""


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

    def info(self, m): self._w(Text.assemble(("[*] ", "blue"), m))
    def ok(self, m): self._w(Text.assemble(("[+] ", "green"), m))
    def warn(self, m): self._w(Text.assemble(("[!] ", "yellow"), m))
    def error(self, m): self._w(Text.assemble(("[-] ", "red"), m))
    def line(self, m=""): self._w(Text(m))
    def title(self, m): self._w(Text("\n" + m, style="bold"))

    def table(self, headers, rows):
        t = Table(*headers, show_edge=False, header_style="bold", expand=False)
        for r in rows:
            t.add_row(*[Text(str(c)) for c in r])
        self._w(t)

    def secret(self, label, value):
        self._w(Text.assemble("\n  ", (f"{label}: ", "bold yellow"), (f" {value} ", "bold reverse"), "\n"))

    def check(self, good, m):
        self._w(Text.assemble(("  [OK] " if good else "  [X]  ", "green" if good else "red"), m))


# ---------------------------------------------------------------- ventanas

class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,q,question_mark", "close", "Cerrar")]

    def __init__(self, markdown: str):
        super().__init__()
        self.markdown = markdown

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            with VerticalScroll(id="help-doc"):
                yield Markdown(self.markdown)
            with Horizontal(classes="buttons"):
                yield Button("Cerrar", variant="primary", id="close")

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
        with Vertical(classes="dialog"):
            yield Static("Confirmación", classes="dialog-title")
            yield Static(self.text, markup=False)
            with Horizontal(classes="buttons"):
                yield Button("Cancelar", id="no")
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

    def __init__(self, module: Module, action: Action):
        super().__init__()
        self.module, self.action_def = module, action
        self.params = action.visible_params()

    def compose(self) -> ComposeResult:
        basic = [p for p in self.params if not p.advanced]
        adv = [p for p in self.params if p.advanced]
        with Vertical(classes="dialog"):
            yield Static(f"{self.module.name} › {self.action_def.label}", classes="dialog-title")
            if self.action_def.help:
                yield Static(self.action_def.help, classes="hint")
            yield Static("Intro = aceptar · Esc = cancelar · F1 = ayuda · Espacio = marcar casillas", classes="hint")
            with VerticalScroll(id="form-fields"):
                for p in basic:
                    yield from self._field(p)
                if adv:
                    yield FormCheckbox(f"Mostrar opciones avanzadas ({len(adv)})", False, id="adv-toggle")
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
        if p.kind == "bool":
            yield FormCheckbox(p.label, bool(p.default), id=wid)
        else:
            yield Label(p.label + optional, classes="field-label")
            if p.kind == "choice":
                yield Select([(text, val) for val, text in p.choices], value=p.default or p.choices[0][0],
                             allow_blank=False, id=wid)
            elif p.kind in ("user", "group"):
                names = accounts.human_names() if p.kind == "user" else \
                    [g.gr_name for g in accounts.local_groups()]
                yield Input(str(p.default or ""), id=wid, suggester=SuggestFromList(names),
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
                yield Input(str(p.default if p.default is not None else ""), id=wid, password=p.kind == "password",
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
            self.query_one("#adv-box").display = False
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
            self.query_one("#error", Static).update(problem)
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


# ---------------------------------------------------------------- catálogo

class CatalogScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Volver"), Binding("r", "rescan", "Volver a detectar"),
                Binding("i", "install", "Instalar lo que falta"), Binding("o", "install_optional", "Instalar opcionales"),
                Binding("v", "toggle", "Mostrar/ocultar"),
                Binding("question_mark", "help", "Ayuda")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Catálogo de módulos: estado en este equipo. Selecciona uno y usa los botones.",
                     id="mod-summary")
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
            t.add_row(m.name, m.category, state, "no" if m.id in hidden else "sí", detail, key=m.id)

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


class ResultsScreen(Screen):
    """Resultados guardados de todos los módulos: escaneos, análisis, informes y evidencias."""
    BINDINGS = [Binding("escape", "back", "Volver"), Binding("question_mark", "help", "Ayuda")]
    TEXT_EXT = (".txt", ".nmap", ".log", ".json", ".jsonl", ".csv", ".dat", ".sha256", ".gnmap")

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Resultados guardados (más recientes primero). Intro abre; Esc vuelve.", id="mod-summary")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield DataTable(id="res-sessions", cursor_type="row", zebra_stripes=True)
            with Vertical(id="main"):
                yield OptionList(id="res-files")
                yield RichLog(id="res-view", wrap=False, markup=False, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#sidebar").styles.width = 58
        t = self.query_one("#res-sessions", DataTable)
        t.add_columns("Módulo", "Fecha", "Qué")
        self.sessions = results.all_sessions(300)
        for i, (mod, d) in enumerate(self.sessions):
            n = d.name
            t.add_row(mod, f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}", n[16:][:28], key=str(i))
        if not self.sessions:
            self.query_one("#res-view", RichLog).write("Todavía no hay resultados guardados.")
        t.focus()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        _, d = self.sessions[int(event.row_key.value)]
        files = sorted(p for p in d.rglob("*") if p.is_file())
        ol = self.query_one("#res-files", OptionList)
        ol.clear_options()
        self.files = files
        for i, f in enumerate(files):
            ol.add_option(Option(f"{f.relative_to(d)}  ({max(1, f.stat().st_size // 1024)} KB)", id=str(i)))
        ol.styles.max_height = min(10, max(3, len(files) + 2))
        log = self.query_one("#res-view", RichLog)
        log.clear()
        log.write(f"{d}")

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
            f"`{results.ROOT}` (solo root).\n\n1. Elige una ejecución en la lista de la izquierda.\n"
            "2. Intro y elige un fichero para verlo.\n\nSe conservan los últimos "
            f"{config.settings().getint('resultados', 'conservar_por_modulo', fallback=50)} por módulo "
            "(se cambia en la configuración). Los informes CSV e inventarios están en "
            f"`{paths.REPORT_DIR}` y las copias en `{paths.BACKUP_DIR}`."))


class LogScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,q", "close", "Cerrar")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(f"Últimos cambios registrados ({paths.AUDIT_LOG})", classes="dialog-title")
            t = DataTable(zebra_stripes=True)
            yield t
            with Horizontal(classes="buttons"):
                yield Button("Cerrar", variant="primary")

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("Fecha", "Operador", "Acción", "Objetivo", "Resultado", "Detalle")
        for r in reversed(audit.read(200)):
            t.add_row(Text(r.get("fecha", "")[:19].replace("T", " ")),
                      *[Text(str(r.get(k, ""))) for k in ("operador", "accion", "objetivo", "resultado", "detalle")])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- aplicación

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
        Binding("escape", "back_to_modules", "Volver a módulos", show=False),
        Binding("question_mark", "help", "Ayuda (?)", key_display="?"),
        Binding("c", "catalog", "Catálogo"),
        Binding("r", "rescan", "Volver a detectar"),
        Binding("g", "results", "Resultados"),
        Binding("l", "log", "Registro"),
        Binding("s", "stop", "Detener"),
        Binding("q", "quit", "Salir"),
    ]

    def check_action(self, action: str, parameters) -> Optional[bool]:
        # Con una ventana abierta (formulario, confirmación, ayuda) o en el catálogo, las teclas
        # globales no actúan: así 'q' o 'c' nunca cierran ni cambian nada por accidente.
        if action == "back_to_modules":
            return isinstance(self.screen, MainScreen)
        if action in ("help", "catalog", "rescan", "log", "quit", "stop", "results") and not isinstance(self.screen, MainScreen):
            return False
        if action == "stop":
            return bool(self.running)      # solo aparece mientras algo se ejecuta
        if action in ("catalog", "rescan", "quit") and self.running:
            return False
        return True

    def __init__(self):
        super().__init__()
        self.modules: list[Module] = []
        self.current: Optional[Module] = None
        self.main: Optional[MainScreen] = None
        self.running = False

    def on_mount(self) -> None:
        self.push_screen(MainScreen())

    def compose_main(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("Módulos", classes="section")
                yield OptionList(id="modules")
            with Vertical(id="main"):
                yield Static("", id="mod-title")
                yield Static("", id="mod-summary")
                yield OptionList(id="actions")
                yield RichLog(id="output", wrap=True, markup=False, highlight=False)
                yield Static("", id="status")
        yield Footer()

    def main_ready(self) -> None:
        self.sub_title = f"{system.hostname()} · {system.os_pretty()} · operador: {system.operator()} · edición {edition.current()} · v{VERSION}"
        self.reload_modules()
        self.main.query_one("#output", RichLog).write(Text(
            "Elige un módulo a la izquierda. Pulsa ? para ver la ayuda de lo que tengas seleccionado.", style="bold"))
        if not system.is_root():
            self.main.query_one("#output", RichLog).write(Text(
                "Aviso: no eres root. Puedes consultar, pero las acciones que cambian algo fallarán. "
                f"Cierra y abre la herramienta escribiendo solo: {NAME}", style="yellow"))
        self.main.query_one("#modules", OptionList).focus()

    # -- módulos

    def reload_modules(self) -> None:
        hidden = config.hidden_modules()
        mods = all_modules()
        self.modules = [m for m in mods if m.id not in hidden and m.status().state == AVAILABLE]
        extra = [m for m in mods if m.status().state == INSTALLABLE and m.id not in hidden]
        ol = self.main.query_one("#modules", OptionList)
        ol.clear_options()
        for cat in CATEGORIES:
            items = [m for m in self.modules if m.category == cat]
            if not items:
                continue
            ol.add_option(Option(Text(cat.upper(), style="bold dim"), disabled=True))
            for m in items:
                ol.add_option(Option(f"  {m.name}", id=m.id))
        ol.add_option(None)
        label = "  Catálogo y configuración"
        if extra:
            label += f"  (+{len(extra)} instalables)"
        ol.add_option(Option(label, id="__catalog__"))
        self.main.query_one("#status", Static).update(
            f"{len(self.modules)} módulos disponibles · {len(extra)} instalables · detección: al abrir y con la tecla r")

    def show_module(self, m: Module) -> None:
        self.current = m
        self.main.query_one("#mod-title", Static).update(m.name)
        self.main.query_one("#mod-summary", Static).update(m.summary + "   ·   ? = ayuda")
        acts = self.main.query_one("#actions", OptionList)
        acts.clear_options()
        group = None
        for a in m.actions():
            if not a.available():
                continue
            if a.group and a.group != group:
                group = a.group
                acts.add_option(Option(Text(a.group.upper(), style="bold dim"), disabled=True))
            mark = Text(" ●", style="yellow") if a.changes else Text("")
            acts.add_option(Option(Text.assemble("  " if a.group else "", a.label, mark), id=a.id))
        first = next((i for i in range(acts.option_count) if not acts.get_option_at_index(i).disabled), None)
        if first is not None:
            acts.highlighted = first

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_list.id == "modules" and event.option_id and event.option_id != "__catalog__":
            m = next((x for x in self.modules if x.id == event.option_id), None)
            if m and m is not self.current:
                self.show_module(m)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "modules":
            if event.option_id == "__catalog__":
                self.action_catalog()
                return
            m = next((x for x in self.modules if x.id == event.option_id), None)
            if m:
                self.show_module(m)
                self.main.query_one("#actions", OptionList).focus()
        elif event.option_list.id == "actions" and self.current:
            a = self.current.action(event.option_id or "")
            if a:
                self.start_action(self.current, a)

    def action_back_to_modules(self) -> None:
        # Esc en la pantalla principal: si el foco está en la lista de acciones, vuelve a la de módulos.
        if not isinstance(self.screen, MainScreen) or not self.main:
            return
        acts = self.main.query_one("#actions", OptionList)
        if acts.has_focus:
            self.main.query_one("#modules", OptionList).focus()

    # -- acciones

    def start_action(self, m: Module, a: Action) -> None:
        if self.running:
            self.notify("Espera a que termine la acción en curso.", severity="warning")
            return
        if a.visible_params():
            self.push_screen(FormScreen(m, a), lambda vals: vals is not None and self.confirm_and_run(m, a, vals))
        else:
            self.confirm_and_run(m, a, {})

    def confirm_and_run(self, m: Module, a: Action, vals: dict) -> None:
        text = a.confirm_text({**{p.name: p.default for p in a.params}, **vals})
        if text:
            self.push_screen(ConfirmScreen(text), lambda yes: yes and self.launch_action(m, a, vals))
        else:
            self.launch_action(m, a, vals)

    def launch_action(self, m: Module, a: Action, vals: dict) -> None:
        out = self.main.query_one("#output", RichLog)
        out.write(Text(f"\n── {m.name} › {a.label} ──", style="bold cyan"))
        self.running = True
        self.refresh_bindings()
        self.main.query_one("#status", Static).update(f"Ejecutando: {a.label}...   ·   s = detener")
        self._worker(m, a, vals)

    @work(thread=True, exclusive=True, group="action")
    def _worker(self, m: Module, a: Action, vals: dict) -> None:
        out = self.main.query_one("#output", RichLog)
        ok = execute(m, a, dict(vals), Context(TuiOut(self, out)))
        self.call_from_thread(self._done, a, ok)

    def _done(self, a: Action, ok: bool) -> None:
        self.running = False
        self.refresh_bindings()
        self.main.query_one("#status", Static).update(
            f"{'Terminado' if ok else 'Terminado con errores'}: {a.label}   ·   ? = ayuda")
        if a.changes:
            self.reload_modules()

    # -- teclas

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

    def action_catalog(self) -> None:
        self.push_screen(CatalogScreen())

    def action_rescan(self) -> None:
        self.reload_modules()
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


def run() -> int:
    OpsdeckApp().run()
    return 0
