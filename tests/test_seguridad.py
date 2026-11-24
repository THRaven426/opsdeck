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
