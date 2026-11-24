"""Pruebas de los arreglos de seguridad y robustez: marcado de Rich con datos externos, secretos de
netexec, nombres de reglas sudo y validación de nombres que se pasan a realm."""
import glob
import os
import tempfile

os.environ.setdefault("OPSDECK_DATA", "/tmp/od/data")
os.environ.setdefault("OPSDECK_LOG", "/tmp/od/log")
os.environ.setdefault("OPSDECK_CONF", "/tmp/od/od.conf")


class Out:
    def __init__(self):
        self.msgs = []

    def __getattr__(self, name):
        return lambda *a, **k: self.msgs.append((name, a))


class Ctx:
    def __init__(self):
        self.out = Out()


def test_salida_cli_no_interpreta_marcado(capsys):
    from opsdeck.cli import ConsoleOut
    o = ConsoleOut()
    o.error("Objetivo no válido: '[/x]'")
    o.info("Server: [bold]nginx[/bold]")
    o.table(["Recurso"], [["datos [/red]"]])
    o.check(False, "[x] cookie")
    out = capsys.readouterr().out
    assert "[/x]" in out and "[bold]nginx[/bold]" in out and "datos [/red]" in out


def test_fichero_sudo_sin_puntos():
    from opsdeck.modules import usuarios
    assert usuarios._sudo_file("juan").name == "90-opsdeck-juan"
    f = usuarios._sudo_file("juan.perez")
    assert "." not in f.name and not f.name.endswith("~") and f.name == "90-opsdeck-juan_2eperez"
    assert usuarios._legacy_sudo_file("juan.perez").name == "90-opsdeck-juan.perez"


def _netexec_env(monkeypatch, tmp_path):
    from opsdeck.modules import smb
    calls = []
    monkeypatch.setattr(smb.scope, "gate", lambda *a, **k: True)
    monkeypatch.setattr(smb, "_targets", lambda ctx, t: t.split())
    monkeypatch.setattr(smb.system, "has_cmd", lambda c: c == "netexec")
    monkeypatch.setattr(smb.results, "new_dir", lambda *a, **k: tmp_path)

    def fake_stream(ctx, args, **k):
        files = [a for a in args if a.startswith(tempfile.gettempdir() + "/opsdeck-nxc-")]
        calls.append((list(args), {f: open(f).read() for f in files}))
        return 0, ""
    monkeypatch.setattr(smb, "stream", fake_stream)
    return smb, calls


def _nxc_files():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "opsdeck-nxc-*")))


def test_netexec_hash_y_password_por_fichero(monkeypatch, tmp_path):
    smb, calls = _netexec_env(monkeypatch, tmp_path)
    before = _nxc_files()
    h = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    assert smb.netexec(Ctx(), {"objetivo": "10.0.0.5", "protocolo": "smb", "usuario": "EMP\\ana", "hash": h})
    args, files = calls[-1]
    assert h not in args and "-H" in args and list(files.values()) == [h + "\n"]
    assert smb.netexec(Ctx(), {"objetivo": "10.0.0.5", "protocolo": "smb", "usuario": "ana", "password": "S3creta!"})
    args, files = calls[-1]
    assert "S3creta!" not in args and "-p" in args and list(files.values()) == ["S3creta!\n"]
    assert _nxc_files() == before, "quedó un fichero temporal con credenciales"


def test_netexec_no_deja_secretos_si_falla_la_validacion(monkeypatch, tmp_path):
    smb, calls = _netexec_env(monkeypatch, tmp_path)
    before = _nxc_files()
    assert not smb.netexec(Ctx(), {"objetivo": "10.0.0.5", "protocolo": "smb", "usuario": "ana",
                                   "password": "S3creta!", "extra": "-x whoami"})
    assert not calls and _nxc_files() == before


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
