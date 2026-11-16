"""Pruebas de la interfaz con el simulador de Textual (sin terminal real)."""
import asyncio
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
    assert opened > 40


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
