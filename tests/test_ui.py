"""Pruebas de la interfaz con el simulador de Textual (sin terminal real)."""
import os

import pytest

os.environ.setdefault("OPSDECK_DATA", "/tmp/od/data")
os.environ.setdefault("OPSDECK_LOG", "/tmp/od/log")
os.environ.setdefault("OPSDECK_CONF", "/tmp/od/od.conf")

from textual.widgets import OptionList, RichLog  # noqa: E402

from opsdeck.ui.app import CatalogScreen, ConfirmScreen, FormScreen, HelpScreen, OpsdeckApp  # noqa: E402


def output_text(app) -> str:
    log = app.main.query_one("#output", RichLog)
    return "\n".join(str(line.text) for line in log.lines)


async def wait_idle(pilot, app):
    for _ in range(60):
        await pilot.pause(0.1)
        if not app.running:
            return


@pytest.mark.asyncio
async def test_navegar_y_ejecutar_resumen():
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        ids = [mods.get_option_at_index(i).id for i in range(mods.option_count)]
        assert "sistema" in ids and "usuarios" in ids and "__catalog__" in ids
        mods.highlighted = ids.index("sistema")
        await pilot.press("enter")
        await pilot.pause()
        assert app.current.id == "sistema"
        acts = app.main.query_one("#actions", OptionList)
        assert app.focused is acts
        acts.highlighted = 0
        await pilot.press("enter")
        await wait_idle(pilot, app)
        assert "Kernel" in output_text(app)


@pytest.mark.asyncio
async def test_formulario_ficha_y_ayuda():
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        ids = [mods.get_option_at_index(i).id for i in range(mods.option_count)]
        mods.highlighted = ids.index("usuarios")
        await pilot.press("enter")
        acts = app.main.query_one("#actions", OptionList)
        aids = [acts.get_option_at_index(i).id for i in range(acts.option_count)]
        acts.highlighted = aids.index("ficha")
        # ayuda contextual de la acción
        await pilot.press("question_mark")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await pilot.pause()
        # formulario
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FormScreen)
        await pilot.press("enter")            # vacío: debe quejarse y no cerrar
        await pilot.pause()
        assert isinstance(app.screen, FormScreen)
        await pilot.press(*"root")
        await pilot.press("enter")
        await wait_idle(pilot, app)
        assert "Usuario root" in output_text(app)


@pytest.mark.asyncio
async def test_confirmacion_cancelada_no_hace_nada_y_q_no_sale():
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        ids = [mods.get_option_at_index(i).id for i in range(mods.option_count)]
        mods.highlighted = ids.index("sistema")
        await pilot.press("enter")
        acts = app.main.query_one("#actions", OptionList)
        aids = [acts.get_option_at_index(i).id for i in range(acts.option_count)]
        acts.highlighted = aids.index("actualizar")
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("q")                 # no debe cerrar la aplicación
        await pilot.pause()
        assert app.is_running and isinstance(app.screen, ConfirmScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert "Instalar actualizaciones" not in output_text(app)


@pytest.mark.asyncio
async def test_catalogo():
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, CatalogScreen)
        assert app.screen.query_one("DataTable").row_count >= 3
        await pilot.press("question_mark")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is app.main


@pytest.mark.skipif(not os.environ.get("OPSDECK_TEST_INSTALL"), reason="instala paquetes reales: OPSDECK_TEST_INSTALL=1")
async def test_instalar_desde_catalogo_y_aparece_en_menu():
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        assert "rdp" not in [mods.get_option_at_index(i).id for i in range(mods.option_count)]
        await pilot.press("c")
        await pilot.pause()
        table = app.screen.query_one("DataTable")
        keys = [table.coordinate_to_cell_key((r, 0)).row_key.value for r in range(table.row_count)]
        table.move_cursor(row=keys.index("rdp"))
        await pilot.press("i")
        for _ in range(300):
            await pilot.pause(0.2)
            if isinstance(app.screen, ConfirmScreen):
                break
        assert isinstance(app.screen, ConfirmScreen), "no apareció la confirmación con el plan"
        await pilot.click("#yes")
        for _ in range(600):
            await pilot.pause(0.2)
            if app.screen.query_one("DataTable") and "disponible" in str(
                    app.screen.query_one("DataTable").get_row("rdp")[2]):
                break
        await pilot.press("escape")
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        assert "rdp" in [mods.get_option_at_index(i).id for i in range(mods.option_count)]


async def test_todos_los_formularios_se_abren_y_cierran():
    """Recorre todos los módulos disponibles y abre el formulario de cada acción con datos."""
    from opsdeck.core.catalog import AVAILABLE, all_modules
    app = OpsdeckApp()
    opened = 0
    expected = sum(1 for m in all_modules() if m.status().state == AVAILABLE
                   for a in m.actions() if a.available() and a.visible_params())
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        for m in all_modules():
            if m.status().state != AVAILABLE:
                continue
            for a in m.actions():
                if not a.available() or not a.visible_params():
                    continue
                app.push_screen(FormScreen(m, a))
                await pilot.pause()
                assert isinstance(app.screen, FormScreen), f"{m.id}.{a.id}"
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is app.main, f"{m.id}.{a.id} no se cerró"
                opened += 1
    assert expected > 0 and opened == expected


async def test_resultados_y_grupos():
    from opsdeck.ui.app import ResultsScreen
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        mods = app.main.query_one("#modules", OptionList)
        ids = [mods.get_option_at_index(i).id for i in range(mods.option_count)]
        mods.highlighted = ids.index("usuarios")
        await pilot.press("enter")
        acts = app.main.query_one("#actions", OptionList)
        assert acts.get_option_at_index(0).disabled            # encabezado de grupo
        assert acts.highlighted == 1                            # primera acción real
        await pilot.press("g")
        await pilot.pause()
        assert isinstance(app.screen, ResultsScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is app.main


async def test_opciones_avanzadas_ocultas_hasta_pedirlas():
    from textual.widgets import Checkbox, Input
    from opsdeck.core.catalog import module
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        m = module("escaneo")
        a = m.action("escanear")
        app.push_screen(FormScreen(m, a))
        await pilot.pause()
        scr = app.screen
        box = scr.query_one("#adv-box")
        assert not box.display
        assert scr.focused is scr.query_one("#f-objetivo", Input)
        scr.query_one("#adv-toggle", Checkbox).value = True
        await pilot.pause()
        assert box.display
        scr.query_one("#f-puertos", Input).value = "22,443"
        vals = scr.values()
        assert vals["puertos"] == "22,443" and "perfil" in vals and "adv-toggle" not in vals
        await pilot.press("escape")


# ---------------------------------------------------------------- interfaz 2.5

async def test_inicio_busqueda_y_tema():
    from opsdeck.ui.app import SearchScreen
    from textual.widgets import ContentSwitcher
    app = OpsdeckApp()
    async with app.run_test(size=(150, 46)) as pilot:
        await pilot.pause()
        assert app.main.query_one("#views", ContentSwitcher).current == "home"
        assert "Equipo" in app.main.query_one("#card-host").border_title
        await pilot.press("slash")
        await pilot.pause()
        assert isinstance(app.screen, SearchScreen)
        await pilot.press(*"ficha usu")          # sin tildes y en cualquier orden
        await pilot.pause()
        assert [e[2] for e in app.screen.shown] == ["ficha"]
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FormScreen) and app.screen.action_def.id == "ficha"
        await pilot.press("escape")
        await pilot.pause()
        assert app.current.id == "usuarios"
        assert app.main.query_one("#views", ContentSwitcher).current == "module"
        before = app.theme
        await pilot.press("t")
        await pilot.pause()
        assert app.theme != before


async def test_escribir_en_un_campo_no_dispara_teclas():
    from opsdeck.ui.app import SearchScreen
    app = OpsdeckApp()
    async with app.run_test(size=(150, 46)) as pilot:
        await pilot.pause()
        await pilot.press("slash")
        await pilot.pause()
        await pilot.press(*"quit")              # «q» y «u» son letras, no salir ni actualizar
        await pilot.pause()
        assert app.is_running and isinstance(app.screen, SearchScreen)


async def test_vista_previa_y_pestanas_del_modulo():
    from textual.widgets import Markdown, TabbedContent
    app = OpsdeckApp()
    async with app.run_test(size=(150, 46)) as pilot:
        await pilot.pause()
        app.goto_module("sistema")
        await pilot.pause()
        acts = app.main.query_one("#actions", OptionList)
        aids = [acts.get_option_at_index(i).id for i in range(acts.option_count)]
        acts.highlighted = aids.index("actualizar")
        await pilot.pause()
        assert "Cambia el sistema" in app.main.query_one("#action-md", Markdown).source
        acts.highlighted = aids.index("resumen")
        await pilot.press("enter")
        await wait_idle(pilot, app)
        assert app.main.query_one("#tabs", TabbedContent).active == "tab-out"
        assert "Kernel" in output_text(app)


async def test_actualizar_desde_la_interfaz(tmp_path, monkeypatch):
    """Comprobar, ver los cambios, instalar con progreso y pedir el reinicio, con repositorios git reales."""
    import subprocess
    from opsdeck.core import actualizar, system
    from opsdeck.ui import app as ui
    from opsdeck.ui.app import UpdateScreen
    from textual.widgets import Markdown

    ident = ["-c", "user.name=p", "-c", "user.email=p@example.invalid", "-c", "commit.gpgsign=false"]

    def git(repo, *args):
        r = subprocess.run(["git", "-C", str(repo), *ident, *args], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    up = tmp_path / "up"
    (up / "opsdeck").mkdir(parents=True)
    git(tmp_path, "init", "-q", "-b", "main", str(up))
    (up / "opsdeck" / "__init__.py").write_text('VERSION = "2.4.3"\n')
    git(up, "add", ".")
    git(up, "commit", "-qm", "base")
    inst = tmp_path / "inst"
    subprocess.run(["git", "clone", "-q", str(up), str(inst)], check=True)
    git(inst, "remote", "set-url", "origin", "https://example.invalid/opsdeck.git")
    (up / "opsdeck" / "__init__.py").write_text('VERSION = "2.5.0"\n')
    (up / "CHANGELOG.md").write_text("# Registro\n\n## 2.5.0 — hoy\n\n- Novedad visible \x1b[31m\n\n## 2.4.3 — ayer\n\n- vieja\n")
    git(up, "add", ".")
    git(up, "commit", "-qm", "nueva")
    real_run = system.run

    def fake_run(cmd, **kw):
        if "fetch" in cmd:
            return real_run(["git", "-C", str(inst), "fetch", "--quiet", str(up), "+refs/heads/main:refs/remotes/origin/main"])
        return real_run(cmd, **kw)
    monkeypatch.setattr(actualizar.paths, "APP_DIR", inst)
    monkeypatch.setattr(system, "run", fake_run)
    monkeypatch.setattr(ui, "VERSION", "2.4.3")
    monkeypatch.setattr(actualizar.audit, "record", lambda *a, **k: None)

    app = OpsdeckApp()
    async with app.run_test(size=(150, 46)) as pilot:
        await pilot.pause()
        await pilot.press("u")
        for _ in range(50):
            await pilot.pause(0.1)
            if app.update_state is not None:
                break
        await pilot.pause(0.3)
        scr = app.screen
        assert isinstance(scr, UpdateScreen) and app.update_state.hay_nueva
        md = scr.query_one("#upd-md", Markdown).source
        assert "Novedad visible" in md and "vieja" not in md and "\x1b" not in md
        assert app.main.query_one("#update-banner").display
        await pilot.click("#upd-install")
        for _ in range(100):
            await pilot.pause(0.1)
            if app.update_done is not None:
                break
        assert app.update_done and app.update_done.ok
        assert git(inst, "rev-parse", "HEAD") == git(up, "rev-parse", "HEAD")
        assert scr.query_one("#upd-restart").display
        # con un reinicio pendiente no se lanzan acciones con el código a medias
        await pilot.click("#upd-restart")
        await pilot.pause(0.3)
        assert app.restart


async def test_verificar_hallazgos_desde_resultados(tmp_path, monkeypatch):
    from opsdeck.core import edition, results
    from opsdeck.ui.app import ResultsScreen
    monkeypatch.setattr(edition, "allowed_full", lambda: (True, ""))
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    d = results.new_dir("nuclei", "analisis_x")
    (d / "hallazgos.jsonl").write_text('{"template-id": "CVE-2024-6387", "host": "127.0.0.1:22"}\n')
    app = OpsdeckApp()
    async with app.run_test(size=(150, 46)) as pilot:
        await pilot.pause()
        await pilot.press("g")
        await pilot.pause(0.3)
        assert isinstance(app.screen, ResultsScreen) and app.screen.query_one("#res-verify").display
        await pilot.press("v")
        await pilot.pause(0.3)
        assert isinstance(app.screen, FormScreen) and app.screen.action_def.id == "hallazgos"
        vals = app.screen.values()
        assert vals["origen"] == "nuclei" and vals["carpeta"] == d.name
        await pilot.press("escape")
