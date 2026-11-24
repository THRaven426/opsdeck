"""LDAP: certificado verificado por defecto y controlador dentro del alcance."""
import ipaddress

from opsdeck.core import scope, system
from opsdeck.modules import ldap


class Out:
    def __init__(self):
        self.msgs = []

    def __getattr__(self, name):
        return lambda *a: self.msgs.append((name, a))


class Ctx:
    def __init__(self):
        self.out = Out()
        self.interactive = False


BASE = {"servidor": "10.0.0.10", "usuario": "consulta@empresa.local", "password": "x", "cifrado": "ldaps"}


def _env_of(monkeypatch, v):
    seen = {}

    def fake_run(args, **kw):
        seen["env"] = kw.get("env") or {}
        seen["args"] = args
        return system.Result(0, "", "")
    monkeypatch.setattr(system, "run", fake_run)
    ldap.Conn(v).search("(objectClass=*)", ["cn"])
    return seen


def test_verifica_certificado_por_defecto(monkeypatch):
    seen = _env_of(monkeypatch, BASE)
    assert seen["env"]["LDAPTLS_REQCERT"] == "demand"
    assert "x" not in seen["args"]


def test_sin_verificar_solo_si_se_pide(monkeypatch, tmp_path):
    assert _env_of(monkeypatch, {**BASE, "sin_verificar": True})["env"]["LDAPTLS_REQCERT"] == "allow"
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    assert _env_of(monkeypatch, {**BASE, "ca": str(ca)})["env"]["LDAPTLS_CACERT"] == str(ca)


def test_controlador_fuera_de_alcance_se_bloquea(monkeypatch):
    monkeypatch.setattr(scope, "authorized_networks", lambda: [ipaddress.ip_network("192.168.1.0/24")])
    monkeypatch.setattr(scope.audit, "record", lambda *a: None)
    assert ldap._conn(Ctx(), dict(BASE)) is None
    assert ldap._conn(Ctx(), {**BASE, "servidor": "192.168.1.5"}) is not None


def test_servidor_no_valido():
    for bad in ("-H ldap://otro", "dc01/evil", "dc01\nx"):
        assert ldap.Conn({**BASE, "servidor": bad}).problem()
    assert not ldap.Conn({**BASE, "servidor": "dc01.empresa.local:636"}).problem()
