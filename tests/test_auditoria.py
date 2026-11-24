"""Segunda auditoría: lecturas seguras como root, acceso remoto, servicios críticos, sudoers y registros."""
import os

import pytest

from opsdeck.core import results, safeio, scope, system, tooling


class Out:
    def __init__(self):
        self.msgs = []

    def __getattr__(self, name):
        return lambda *a, **k: self.msgs.append((name, a))

    def text(self):
        return " ".join(str(a) for _, args in self.msgs for a in args)


class Ctx:
    def __init__(self):
        self.out = Out()
        self.interactive = False


def test_safeio_no_sigue_enlaces_ni_se_cuelga(tmp_path):
    secreto = tmp_path / "secreto"
    secreto.write_text("hash")
    enlace = tmp_path / "enlace"
    enlace.symlink_to(secreto)
    with pytest.raises(safeio.UnsafeFile):
        safeio.read_text(enlace)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(safeio.UnsafeFile):
        safeio.read_text(fifo)                       # no se bloquea esperando a un escritor
    grande = tmp_path / "grande"
    grande.write_bytes(b"x" * 5000)
    assert len(safeio.read_bytes(grande, 100)) == 100
    assert safeio.sha256(grande)[1] == 5000


def test_lista_de_objetivos_enlazada_se_rechaza(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("10.0.0.5\n")
    real.chmod(0o644)
    link = tmp_path / "lista.txt"
    link.symlink_to(real)
    specs, problem = scope.read_target_file(str(link))
    assert not specs and "enlace" in problem


def test_operador_sale_de_la_sesion_no_de_sudo_user(monkeypatch):
    monkeypatch.setattr(system, "_login_user", lambda: "ana")
    monkeypatch.setenv("SUDO_USER", "root")
    assert system.operator() == "ana"
    monkeypatch.setattr(system, "_login_user", lambda: None)
    assert system.operator() == "root"


def test_csv_sin_formulas():
    assert results.csv_safe(["=HYPERLINK(\"x\")", "-3", "+1 555", "@SUM(1)", "ana"]) == \
        ["'=HYPERLINK(\"x\")", "-3", "'+1 555", "'@SUM(1)", "ana"]


def test_ordenes_sin_secretos():
    shown = tooling.redact(["-H", "Authorization: Bearer abc", "-H", "Cookie: s=1", "-proxy", "http://u:p@h:8080",
                            "--script-args", "smbuser=a,smbpass=s3cr"])
    assert "abc" not in str(shown) and "s=1" not in str(shown) and "u:p@" not in str(shown) and "s3cr" not in str(shown)


def _fake_ss(monkeypatch, fw):
    def fake(cmd, **k):
        if cmd[:2] == ["ss", "-ltnpH"]:
            return system.Result(0, 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n', "")
        if cmd[:2] == ["ss", "-tnH"]:
            return system.Result(0, "0 0 10.0.0.5:2222 192.168.9.7:51515\n", "")
        if cmd[-1] == "-T":
            return system.Result(0, "port 2222\n", "")
        return system.Result(0, "", "")
    monkeypatch.setattr(fw.system, "run", fake)
    monkeypatch.setattr(fw.system, "has_cmd", lambda n: n in ("ss", "sshd", "ufw"))
    monkeypatch.setattr(fw.system, "which", lambda n: n)


def test_firewall_respeta_el_puerto_real_de_ssh(monkeypatch):
    from opsdeck.modules import firewall as fw
    _fake_ss(monkeypatch, fw)
    assert fw._remote_ports() == [("2222", "SSH")]


def test_firewall_no_deja_fuera_la_sesion_abierta(monkeypatch):
    from opsdeck.modules import firewall as fw
    _fake_ss(monkeypatch, fw)
    applied = []
    monkeypatch.setattr(fw, "apply", lambda *a, **k: applied.append(a) or True)
    ctx = Ctx()
    assert fw.activar(ctx, {"mantener": True, "origen": "10.0.0.0/24"}) is False
    assert not applied and "192.168.9.7" in ctx.out.text()


def test_servicios_criticos_y_opciones(monkeypatch):
    from opsdeck.modules import servicios
    applied = []
    monkeypatch.setattr(servicios, "apply", lambda *a, **k: applied.append(a) or True)
    monkeypatch.setattr(servicios.system, "run", lambda *a, **k: system.Result(0, "x", ""))
    for unit in ("reboot.target", "dbus", "systemd-journald", "-Hroot@otro"):
        assert servicios._control("stop", "x")(Ctx(), {"servicio": unit}) is False, unit
    assert servicios._control("start", "x")(Ctx(), {"servicio": "rescue.target"}) is False
    assert servicios._control("restart", "x")(Ctx(), {"servicio": "cron"})
    assert applied[-1][3] == ["systemctl", "restart", "--", "cron.service"]
    assert "PERDERÁS" in servicios._confirm_stop({"servicio": "ssh.socket"})


def test_no_puedes_darte_grupos_privilegiados(monkeypatch):
    from opsdeck.modules import usuarios
    monkeypatch.setattr(usuarios.acc, "guard", lambda name, allow_self=True: "" if allow_self else "propia")
    monkeypatch.setattr(usuarios.acc, "user", lambda n: object())
    monkeypatch.setattr(usuarios.acc, "group", lambda g: object())
    monkeypatch.setattr(usuarios.acc, "is_member", lambda n, g: False)
    monkeypatch.setattr(usuarios.edition, "group", lambda: "opsdeck-completa")
    applied = []
    monkeypatch.setattr(usuarios, "apply", lambda *a, **k: applied.append(a) or True)
    assert not usuarios.grupo_add(Ctx(), {"usuario": "yo", "grupo": "opsdeck-completa"})
    assert not usuarios.grupo_add(Ctx(), {"usuario": "yo", "grupo": "sudo"})
    assert usuarios.grupo_add(Ctx(), {"usuario": "yo", "grupo": "proyectos"})


def test_sudo_de_grupos_del_dominio_sin_colisiones():
    from opsdeck.modules import dominio
    names = {dominio._sudo_file(g).name for g in ("IT Admins", "it.admins", "it_admins")}
    assert len(names) == 3 and not any("." in n or " " in n for n in names)


def test_registros_solo_de_procesos_de_root(monkeypatch):
    from opsdeck.modules import registros
    calls = []
    monkeypatch.setattr(registros.system, "has_cmd", lambda n: True)
    monkeypatch.setattr(registros, "journal", lambda since, extra=None: calls.append(extra) or iter(()))
    registros._messages("24h")
    assert calls == [["_UID=0"]]


def test_config_insegura_no_se_sobrescribe(tmp_path, monkeypatch):
    from opsdeck.core import config, paths
    f = tmp_path / "od.conf"
    f.write_text("[general]\nedicion = completa\n")
    f.chmod(0o666)
    monkeypatch.setattr(paths, "CONF_FILE", f)
    config.settings.cache_clear()
    try:
        with pytest.raises(PermissionError):
            config.save()
        assert "completa" in f.read_text()
    finally:
        config.settings.cache_clear()
