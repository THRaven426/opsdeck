"""Entradas no confiables que acaban en la línea de comandos o en la consola."""
import ipaddress

from opsdeck.core import informes, scope, tooling
from opsdeck.core.informes import Item


def test_informe_descarta_equipos_que_serian_opciones(tmp_path):
    f = tmp_path / "malo.nessus"
    f.write_text('<NessusClientData_v2><Report>'
                 '<ReportHost name="-oN/etc/passwd"><ReportItem port="80" severity="3" pluginID="1" pluginName="x"/></ReportHost>'
                 '<ReportHost name="10.0.0.5"><ReportItem port="abc" severity="3" pluginID="2" pluginName="y"/></ReportHost>'
                 '</Report></NessusClientData_v2>')
    items, fmt = informes.load(f)
    assert fmt == "nessus" and len(items) == 2
    ok, dropped = informes.split_valid(items)
    assert dropped == 1 and [i.host for i in ok] == ["10.0.0.5"] and ok[0].puerto is None


def test_leer_importacion_antigua_filtra_equipos(tmp_path):
    p = tmp_path / "hallazgos.json"
    informes.save([Item("-iL/etc/shadow", 22, "tcp", "ALTO", "1", "x"), Item("srv01", 22, "tcp", "ALTO", "1", "x")], p)
    assert [i.host for i in informes.read(p)] == ["srv01"]


def test_opciones_extra_forma_larga_y_objetivos_colados(monkeypatch):
    nets = [ipaddress.ip_network("10.0.0.0/24")]
    monkeypatch.setattr(scope, "authorized_networks", lambda: nets)
    for bad in ("--oA /tmp/x", "--iL lista.txt", "-sS 8.8.8.8", "http://203.0.113.9/"):
        assert tooling.extra_args(bad)[1], bad
    args, err = tooling.extra_args("--reason -S 10.0.0.7 --data-length 25")
    assert not err and args[-1] == "25"


def test_consola_escapa_marcado(capsys):
    from opsdeck import cli
    out = cli.ConsoleOut()
    out.info("objetivo [/x] [bold]raro")
    out.table(["a"], [["[/b]"]])
    printed = capsys.readouterr().out
    assert "[/x]" in printed and "[bold]raro" in printed and "[/b]" in printed


def test_config_de_otro_usuario_no_se_carga(tmp_path, monkeypatch):
    from opsdeck.core import config, paths
    f = tmp_path / "od.conf"
    f.write_text("[red]\nredes_autorizadas = 0.0.0.0/0\n")
    f.chmod(0o666)
    monkeypatch.setenv("OPSDECK_CONF", str(f))
    monkeypatch.setattr(paths, "CONF_FILE", f)
    config.settings.cache_clear()
    try:
        assert config.settings().get("red", "redes_autorizadas") == ""
        f.chmod(0o644)
        config.settings.cache_clear()
        assert config.settings().get("red", "redes_autorizadas") == "0.0.0.0/0"
        config.settings().set("ldap", "usuario", "cuenta%con%porcentaje") if config.settings().has_section("ldap") \
            else config.settings().read_dict({"ldap": {"usuario": "cuenta%con%porcentaje"}})
        config.save()
        assert "cuenta%con%porcentaje" in f.read_text()
    finally:
        config.settings.cache_clear()


class Out:
    def __init__(self):
        self.msgs = []

    def __getattr__(self, name):
        return lambda *a, **k: self.msgs.append((name, a))


class Ctx:
    def __init__(self):
        self.out = Out()



def test_fichero_sudo_sin_puntos():
    from opsdeck.modules import usuarios
    assert usuarios._sudo_file("juan").name == "90-opsdeck-juan"
    f = usuarios._sudo_file("juan.perez")
    assert "." not in f.name and not f.name.endswith("~") and f.name == "90-opsdeck-juan_2eperez"
    assert usuarios._legacy_sudo_file("juan.perez").name == "90-opsdeck-juan.perez"


def test_realm_no_recibe_opciones_como_nombre(monkeypatch):
    from opsdeck.modules import dominio
    applied = []
    monkeypatch.setattr(dominio, "joined", lambda: {"nombre": "empresa.local"})
    monkeypatch.setattr(dominio, "apply", lambda *a, **k: applied.append(a) or True)
    assert not dominio.retirar(Ctx(), {"nombre": "--all", "tipo": "grupo"})
    assert not dominio.permitir(Ctx(), {"nombre": "-x", "tipo": "grupo"})
    assert not applied
    assert dominio.retirar(Ctx(), {"nombre": "Acceso Linux", "tipo": "grupo"})
    assert applied[-1][3] == ["realm", "permit", "--withdraw", "-g", "Acceso Linux"]


def test_restablecer_no_toca_root():
    from opsdeck.modules import usuarios
    ctx = Ctx()
    assert not usuarios.restablecer(ctx, {"usuario": "root", "modo": "generar", "forzar": False})
    assert any(k == "error" and "UID 0" in a[0] for k, a in ctx.out.msgs)


async def test_tui_muestra_datos_con_corchetes():
    from textual.widgets import RichLog

    from opsdeck.ui.app import ConfirmScreen, OpsdeckApp, TuiOut
    app = OpsdeckApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.push_screen(ConfirmScreen("¿Detener 'svc[/x]'?"))
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("escape")
        await pilot.pause()
        log = app.main.query_one("#output", RichLog)
        out = TuiOut(app, log)
        out._w = log.write
        out.table(["Recurso"], [["datos [/red]"]])
        await pilot.pause()
        assert any("datos [/red]" in line.text for line in log.lines)
