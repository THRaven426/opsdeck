"""Pruebas de la revisión unificada de dominio y el diagnóstico de contraseña caducada.

No hay dominio real: se prueba la lógica y el parsing con las salidas de los comandos simuladas."""

from opsdeck.modules import dominio as D


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
    def check(self, good, m): self.msgs.append(("check", (bool(good), m)))

    def kinds(self): return [k for k, _ in self.msgs]
    def checks(self): return [v for k, v in self.msgs if k == "check"]
    def has_title(self, sub): return any(k == "title" and sub in str(m) for k, m in self.msgs)


class Ctx:
    def __init__(self):
        self.out = FakeOut()
        self.interactive = True


# ---------------------------------------------------------------- revisar: despacho según estado

def test_revisar_unido_llama_a_verificar(monkeypatch):
    llamado = {}
    monkeypatch.setattr(D, "joined", lambda: {"nombre": "empresa.local"})
    monkeypatch.setattr(D, "verificar", lambda ctx, v: llamado.setdefault("verificar", True) or True)
    assert D.revisar(Ctx(), {}) is True
    assert llamado.get("verificar")


def test_revisar_no_unido_comprueba_preparacion(monkeypatch):
    llamado = {}
    monkeypatch.setattr(D, "joined", lambda: {})
    monkeypatch.setattr(D, "comprobar", lambda ctx, v: llamado.setdefault("dom", v["dominio"]) or True)
    monkeypatch.setattr(D, "_missing_pkgs", lambda: [])
    monkeypatch.setattr(D, "_fqdn_ok", lambda: (True, "kali.empresa.local"))
    ctx = Ctx()
    D.revisar(ctx, {"dominio": "empresa.local"})
    assert llamado["dom"] == "empresa.local"
    # añade comprobaciones de paquetes y FQDN
    assert any("instaladas" in str(m) for _, m in ctx.out.checks())


def test_revisar_no_unido_sin_dominio_no_falla(monkeypatch):
    monkeypatch.setattr(D, "joined", lambda: {})
    monkeypatch.setattr(D, "_domain_guess", lambda: [])
    ctx = Ctx()
    assert D.revisar(ctx, {}) is True
    assert "info" in ctx.out.kinds()


# ---------------------------------------------------------------- diagnóstico de contraseña caducada

def test_diagnostico_todo_bien(monkeypatch):
    monkeypatch.setattr(D, "joined", lambda: {"nombre": "empresa.local"})
    monkeypatch.setattr(D, "sssd_get", lambda sec, k, d="": "ad" if k == "chpass_provider" else d)
    monkeypatch.setattr(D, "_sshd_effective", lambda k: "yes")
    ctx = Ctx()
    assert D.diagnosticar(ctx, {}) is True
    assert "ok" in ctx.out.kinds()
    assert not ctx.out.has_title("Qué conviene hacer")


def test_diagnostico_sssd_mal(monkeypatch):
    monkeypatch.setattr(D, "joined", lambda: {"nombre": "empresa.local"})
    monkeypatch.setattr(D, "sssd_get", lambda sec, k, d="": "ldap" if k == "chpass_provider" else d)
    monkeypatch.setattr(D, "_sshd_effective", lambda k: "yes")
    ctx = Ctx()
    D.diagnosticar(ctx, {})
    assert ctx.out.has_title("Qué conviene hacer")
    assert any(not good for good, _ in ctx.out.checks())


def test_diagnostico_ssh_mal(monkeypatch):
    monkeypatch.setattr(D, "joined", lambda: {"nombre": "empresa.local"})
    monkeypatch.setattr(D, "sssd_get", lambda sec, k, d="": "ad" if k == "chpass_provider" else d)
    monkeypatch.setattr(D, "_sshd_effective", lambda k: "no" if k == "usepam" else "yes")
    ctx = Ctx()
    D.diagnosticar(ctx, {})
    assert ctx.out.has_title("Qué conviene hacer")


# ---------------------------------------------------------------- helpers

def test_sshd_effective_parsea(monkeypatch):
    class R:
        ok = True
        out = "usepam yes\nkbdinteractiveauthentication yes\npermitrootlogin no\n"
    monkeypatch.setattr(D.system, "run", lambda *a, **k: R())
    assert D._sshd_effective("usepam") == "yes"
    assert D._sshd_effective("KbdInteractiveAuthentication") == "yes"
    assert D._sshd_effective("permitrootlogin") == "no"


def test_sshd_effective_sin_sshd(monkeypatch):
    class R:
        ok = False
        out = ""
    monkeypatch.setattr(D.system, "run", lambda *a, **k: R())
    assert D._sshd_effective("usepam") == ""


def test_fqdn_ok(monkeypatch):
    class R:
        def __init__(s, o): s.out = o
    monkeypatch.setattr(D.system, "run", lambda *a, **k: R("kali.empresa.local\n"))
    ok, name = D._fqdn_ok()
    assert ok and name == "kali.empresa.local"
    monkeypatch.setattr(D.system, "run", lambda *a, **k: R("kali\n"))
    ok, name = D._fqdn_ok()
    assert not ok


def test_missing_pkgs(monkeypatch):
    monkeypatch.setattr(D.system, "has_cmd", lambda n: n in ("sssd", "realm"))
    faltan = D._missing_pkgs()
    assert "adcli" in faltan and "sssd" not in faltan


# ---------------------------------------------------------------- reparto por ediciones

def test_reparto_ediciones():
    acts = {a.id: a for a in D.Dominio().actions()}
    # consultar/diagnosticar: en ambas ediciones
    for a in ("estado", "revisar", "diagnosticar", "probar"):
        assert not acts[a].full, f"{a} no debería ser solo de completa"
    # aplicar cambios: solo completa
    for a in ("unir", "ajustes", "permitir", "retirar", "sudo", "sudo_quitar", "salir"):
        assert acts[a].full, f"{a} debería ser de completa"
