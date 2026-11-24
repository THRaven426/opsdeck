"""Pruebas de la barandilla de alcance (core/scope.py)."""
import ipaddress

import pytest

from opsdeck.core import scope, system


@pytest.fixture(autouse=True)
def operador_root(monkeypatch):
    """Las listas de prueba son de root (quien ejecuta la suite), no de quien usara sudo."""
    monkeypatch.setattr(system, "operator", lambda: "root")


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


class FakeOut:
    def __init__(self):
        self.msgs = []
    def info(self, m=""): self.msgs.append(("info", m))
    def ok(self, m=""): self.msgs.append(("ok", m))
    def warn(self, m=""): self.msgs.append(("warn", m))
    def error(self, m=""): self.msgs.append(("error", m))
    def line(self, m=""): self.msgs.append(("line", m))
    def title(self, m=""): self.msgs.append(("title", m))
    def table(self, h, r): self.msgs.append(("table", h))
    def secret(self, label, value): self.msgs.append(("secret", label))
    def check(self, good, m): self.msgs.append(("check", m))

    def has(self, kind):
        return any(k == kind for k, _ in self.msgs)


class Ctx:
    def __init__(self):
        self.out = FakeOut()
        self.interactive = True


AUT = nets("192.168.1.0/24", "10.20.0.0/16")


@pytest.mark.parametrize("spec,dentro", [
    ("192.168.1.5", True),
    ("192.168.1.1-50", True),          # rango dentro de la /24
    ("192.168.1.0/24", True),
    ("10.20.3.200", True),
    ("10.20.0.0/16", True),
    ("8.8.8.8", False),                # IP pública
    ("1.2.3.0/24", False),             # red ajena
    ("192.168.2.5", False),            # subred contigua pero no autorizada
    ("10.20.0.0/8", False),            # red MAYOR que la autorizada
])
def test_clasificacion(spec, dentro):
    r = scope.classify(spec, AUT)
    if dentro:
        assert r.dentro == [spec] and not r.fuera and not r.sin_resolver
    else:
        assert spec in (r.fuera + r.sin_resolver) and not r.dentro


@pytest.mark.parametrize("spec,dentro", [
    ("10.0.0.0/8", False),             # extremos en redes autorizadas distintas
    ("10.0-255.0.1", False),
    ("10.0.0.0/15", True),             # dos /16 contiguas cubren la /15
    ("10.0.0.5-10", True),
])
def test_rango_entre_redes_separadas(spec, dentro):
    r = scope.classify(spec, nets("10.0.0.0/16", "10.1.0.0/16", "10.255.0.0/16"))
    assert (r.dentro == [spec]) is dentro


def test_bounds_rango_invalido():
    assert scope._ip_bounds("192.168.1.300") is None     # octeto fuera de rango
    assert scope._ip_bounds("192.168.1.50-10") is None   # rango invertido
    assert scope._ip_bounds("no-una-ip") is None


def test_gate_dentro_pasa(monkeypatch):
    monkeypatch.setattr(scope, "authorized_networks", lambda: AUT)
    ctx = Ctx()
    assert scope.gate(ctx, "192.168.1.0/24", {}, "test") is True
    assert not ctx.out.has("error")


def test_gate_fuera_sin_autorizacion_bloquea(monkeypatch):
    monkeypatch.setattr(scope, "authorized_networks", lambda: AUT)
    rec = []
    monkeypatch.setattr(scope.audit, "record", lambda *a, **k: rec.append((a, k)))
    ctx = Ctx()
    assert scope.gate(ctx, "8.8.8.8", {}, "test") is False
    assert ctx.out.has("error")
    assert any("BLOQUEADO" in a for a, k in rec)


def test_gate_fuera_con_autorizacion_pasa_y_registra(monkeypatch):
    monkeypatch.setattr(scope, "authorized_networks", lambda: AUT)
    rec = []
    monkeypatch.setattr(scope.audit, "record", lambda *a, **k: rec.append(a))
    ctx = Ctx()
    assert scope.gate(ctx, "8.8.8.8", {scope.PARAM_OK: True}, "test") is True
    assert ctx.out.has("warn")
    assert any("AUTORIZADO_MANUAL" in a for a in rec)


def test_gate_hostname_sin_resolver_es_fuera(monkeypatch):
    monkeypatch.setattr(scope, "authorized_networks", lambda: AUT)
    monkeypatch.setattr(scope, "_resolve", lambda h: [])   # no resuelve
    monkeypatch.setattr(scope.audit, "record", lambda *a, **k: None)
    ctx = Ctx()
    assert scope.gate(ctx, "equipo.que.no.existe", {}, "test") is False
    assert ctx.out.has("error")


def test_gate_objetivo_vacio_pasa():
    assert scope.gate(Ctx(), "   ", {}, "test") is True


def test_lista_de_objetivos_valida(tmp_path):
    f = tmp_path / "objetivos.txt"
    f.write_text("# red de pruebas\n192.168.1.5 192.168.1.6\n10.20.0.0/24\n")
    f.chmod(0o600)
    r = scope.classify(str(f), AUT)
    assert r.ok and r.dentro == ["192.168.1.5", "192.168.1.6", "10.20.0.0/24"]


def test_lista_con_contenido_ajeno_no_se_repite(tmp_path, monkeypatch):
    f = tmp_path / "shadow"
    f.write_text("root:$6$hashsecreto:19000:0:99999:7:::\n")
    f.chmod(0o600)
    r = scope.classify(str(f), AUT)
    assert not r.ok and not r.dentro and not r.fuera
    assert "hashsecreto" not in " ".join(r.invalidos)
    registrados = []
    monkeypatch.setattr(scope.audit, "record", lambda *a: registrados.append(a))
    ctx = Ctx()
    assert scope.gate(ctx, str(f), {scope.PARAM_OK: True}) is False
    assert "hashsecreto" not in repr(registrados) + repr(ctx.out.msgs)


def test_lista_modificable_por_otros_se_rechaza(tmp_path):
    f = tmp_path / "objetivos.txt"
    f.write_text("192.168.1.5\n")
    f.chmod(0o666)
    r = scope.classify(str(f), AUT)
    assert not r.ok and "modificar" in r.invalidos[0]
