"""authorized_keys: altas y bajas sin seguir enlaces que el usuario pueda colocar."""
import os
import pwd

import pytest

from opsdeck.modules import usuarios

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx0b2RvLWVzLXVuYS1wcnVlYmEtZGUtY2xhdmUtc3No prueba"


@pytest.fixture
def cuenta(tmp_path):
    me = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    home.mkdir()
    return pwd.struct_passwd((me.pw_name, "x", me.pw_uid, me.pw_gid, "", str(home), "/bin/sh"))


def test_anadir_y_leer(cuenta):
    usuarios._append_key(cuenta, KEY)
    f = os.path.join(cuenta.pw_dir, ".ssh", "authorized_keys")
    with open(f) as fh:
        assert fh.read() == KEY + "\n"
    assert oct(os.stat(f).st_mode)[-3:] == "600"
    assert usuarios._read_keys(cuenta) == KEY + "\n"


def test_no_sigue_enlace_en_authorized_keys(cuenta, tmp_path):
    victima = tmp_path / "victima"
    victima.write_text("original\n")
    os.makedirs(os.path.join(cuenta.pw_dir, ".ssh"))
    os.symlink(victima, os.path.join(cuenta.pw_dir, ".ssh", "authorized_keys"))
    with pytest.raises(usuarios._UnsafeSSH):
        usuarios._append_key(cuenta, KEY)
    with pytest.raises(usuarios._UnsafeSSH):
        usuarios._read_keys(cuenta)
    assert victima.read_text() == "original\n"


def test_no_sigue_enlace_en_carpeta_ssh(cuenta, tmp_path):
    otra = tmp_path / "otra"
    otra.mkdir()
    os.symlink(otra, os.path.join(cuenta.pw_dir, ".ssh"))
    with pytest.raises(usuarios._UnsafeSSH):
        usuarios._append_key(cuenta, KEY)
    assert not (otra / "authorized_keys").exists()


def test_reescribir_sustituye_el_fichero(cuenta):
    usuarios._append_key(cuenta, KEY)
    usuarios._rewrite_keys(cuenta, "")
    assert usuarios._read_keys(cuenta) == ""
    assert os.listdir(os.path.join(cuenta.pw_dir, ".ssh")) == ["authorized_keys"]
