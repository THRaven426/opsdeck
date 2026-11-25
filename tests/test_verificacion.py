"""Pruebas del módulo de verificación de vulnerabilidades y de la actualización integrada.
Sin red: los avisos OSV, nuclei y los banners se simulan."""
import json
import os
import socket
import stat
import threading
from pathlib import Path

import pytest

os.environ.setdefault("OPSDECK_DATA", "/tmp/od/data")
os.environ.setdefault("OPSDECK_LOG", "/tmp/od/log")
os.environ.setdefault("OPSDECK_CONF", "/tmp/od/od.conf")

from opsdeck.core import actualizar, debver, feeds, osv, results  # noqa: E402
from opsdeck.core.catalog import Context  # noqa: E402
from opsdeck.modules import verificacion as V  # noqa: E402


class Out:
    def __init__(self):
        self.lines = []

    def __getattr__(self, name):
        return lambda *a, **k: self.lines.append(" ".join(str(x) for x in a))


def ctx():
    return Context(Out())


AVISO_SSH = osv.Aviso("UBUNTU-CVE-2024-6387", "ubuntu", [
    osv.Afectado("openssh", "Ubuntu:22.04:LTS", "1:8.9p1-3ubuntu0.10", ["1:8.9p1-3ubuntu0.7"]),
    osv.Afectado("openssh", "Ubuntu:24.04:LTS", "1:9.6p1-3ubuntu13.3", ["1:9.6p1-3ubuntu13"]),
])


# ---------------------------------------------------------------- versiones

@pytest.mark.parametrize("a,b,res", [
    ("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.3", 1), ("1:9.6p1-3ubuntu13", "1:9.6p1-3ubuntu13.3", -1),
    ("1.0~rc1", "1.0", -1), ("1.2+deb12u10", "1.2+deb12u3", 1), ("2:1.0", "1:9.9", 1), ("1.0", "1.0-0", 0),
    ("5.6.1+really5.4.5-1ubuntu0.4", "5.4.5-0.3", 1),
])
def test_comparacion_como_dpkg(a, b, res):
    c = debver.compare(a, b)
    assert (c > 0) - (c < 0) == res
    assert debver.upstream("1:9.6p1-3ubuntu13.5") == "9.6p1"


# ---------------------------------------------------------------- objetivos y banners

def test_objetivos():
    o, _ = V.parse_objetivo("https://u:clave@10.0.0.5:8443/app")
    assert (o.host, o.port, o.url) == ("10.0.0.5", 8443, "https://10.0.0.5:8443/app")
    assert V.parse_objetivo("10.0.0.5:22")[0].port == 22
    assert V.parse_objetivo("local")[0].local
    for bad in ("-oX", "a b", "http://x:99999", "ftp://x", "10.0.0.5:0", "../etc", "x;id"):
        assert V.parse_objetivo(bad)[0] is None, bad


def test_paquete_del_banner():
    assert V.paquete_de_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5") == ("openssh", "9.6p1-3ubuntu13.5", "ubuntu")
    assert V.paquete_de_banner("OpenSSH 9.2p1 Debian 2+deb12u3") == ("openssh", "9.2p1-2+deb12u3", "debian")
    assert V.paquete_de_banner("SSH-2.0-OpenSSH_9.6") is None          # sin revisión: no se adivina
    assert V.paquete_de_banner("Apache httpd 2.4.58") is None


def test_backport_descarta_falso_positivo(monkeypatch):
    monkeypatch.setattr(osv, "aviso", lambda cve, distro, **k: AVISO_SSH)
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "openssh", "9.6p1-3ubuntu13.5").estado == V.NO_APLICA
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "openssh", "9.6p1-3ubuntu13").estado == V.CONFIRMADA
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "openssh", "8.9p1-3ubuntu0.10").estado == V.NO_APLICA
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "openssh", "7.4p1-1").estado == V.NO_CONCLUYENTE
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "apache2", "2.4.58-1").estado == V.NO_APLICA


def test_backport_sin_datos_no_concluye(monkeypatch):
    monkeypatch.setattr(osv, "aviso", lambda cve, distro, **k: osv.Aviso("x", distro, error="sin red"))
    assert V.comprobar_paquete("CVE-2024-6387", "ubuntu", "openssh", "9.6p1-3ubuntu13").estado == V.NO_CONCLUYENTE


def test_paquetes_de_este_equipo(monkeypatch):
    monkeypatch.setattr(osv, "aviso", lambda cve, distro, **k: AVISO_SSH)
    monkeypatch.setattr(osv, "local_ecosystem", lambda: ("ubuntu", "Ubuntu:24.04:LTS"))
    assert V.comprobar_local("CVE-2024-6387", fuentes={"openssh": "1:9.6p1-3ubuntu13"}).estado == V.CONFIRMADA
    assert V.comprobar_local("CVE-2024-6387", fuentes={"openssh": "1:9.6p1-3ubuntu13.4"}).estado == V.NO_APLICA
    assert V.comprobar_local("CVE-2024-6387", fuentes={"bash": "5.2"}).estado == V.NO_APLICA
    monkeypatch.setattr(osv, "local_ecosystem", lambda: ("ubuntu", "Ubuntu:20.04:LTS"))
    assert V.comprobar_local("CVE-2024-6387", fuentes={"openssh": "1:8.2p1-4ubuntu0.5"}).estado == V.NO_APLICA


def test_aviso_osv_se_guarda_en_cache_privada(tmp_path, monkeypatch):
    monkeypatch.setattr(osv.paths, "DATA_DIR", tmp_path)
    calls = []
    body = json.dumps({"id": "DEBIAN-CVE-2024-6387", "affected": [{"package": {"name": "openssh", "ecosystem": "Debian:12"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}]}]})

    def fake(url, timeout):
        calls.append(url)
        return body.encode(), ""
    monkeypatch.setattr(osv, "_fetch", fake)
    a = osv.aviso("cve-2024-6387", "debian", online=True)
    assert a.afectados[0].corregido == "1:9.2p1-2+deb12u3"
    assert calls == [f"{osv.BASE}/Debian/DEBIAN-CVE-2024-6387.json"]
    f = tmp_path / "cache" / "osv" / "DEBIAN-CVE-2024-6387.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    osv.aviso("CVE-2024-6387", "debian", online=True)
    assert len(calls) == 1                                  # segunda vez, de la caché
    assert osv.aviso("CVE-2024-6387; rm", "debian").error   # nada raro llega a la URL
    assert osv.aviso("CVE-2024-6387", "../../x").error


# ---------------------------------------------------------------- nuclei

TPL = """id: {id}
info:
  name: prueba
  severity: critical
  tags: {tags}
{tipo}:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/{extra}"
"""


@pytest.fixture
def plantillas(tmp_path, monkeypatch):
    base = tmp_path / "nuclei-templates"
    for sub, tags, tipo, extra in (("http/cves/2021", "cve,rce,log4j", "http", "{{interactsh-url}}"),
                                   ("network/cves/2021", "cve,network", "tcp", ""),
                                   ("javascript/cves/2021", "cve", "javascript", ""),
                                   ("http/cves/2020", "cve,intrusive", "http", ""),
                                   ("dast/cves/2021", "cve", "http", "")):
        d = base / sub
        d.mkdir(parents=True)
        (d / "CVE-2021-44228.yaml").write_text(TPL.format(id="CVE-2021-44228", tags=tags, tipo=tipo, extra=extra))
    monkeypatch.setattr(feeds, "NUCLEI_DIRS", [base])
    return base


def test_solo_plantillas_seguras(plantillas):
    by = {str(t.path.relative_to(plantillas).parent): t.motivo for t in V.plantillas_cve("CVE-2021-44228")}
    assert by["network/cves/2021"] == ""
    assert "rce" in by["http/cves/2021"]
    assert "javascript" in by["javascript/cves/2021"]
    assert "intrusive" in by["http/cves/2020"]
    assert "DAST" in by["dast/cves/2021"]
    # con rce permitido sigue haciendo falta un interactsh propio
    by = {str(t.path.relative_to(plantillas).parent): t.motivo for t in V.plantillas_cve("CVE-2021-44228", True)}
    assert "interactsh" in by["http/cves/2021"]
    assert by["http/cves/2021"] and not [m for m in V.plantillas_cve("CVE-2021-44228", True, True)
                                         if m.path.parent.name == "2021" and "http" in str(m.path) and m.motivo
                                         and "dast" not in str(m.path)]


def test_orden_de_nuclei_sin_servidores_publicos(tmp_path):
    t = V.Plantilla(Path("/x/CVE-1.yaml"), set(), {"http"}, False)
    args = V.args_nuclei("https://10.0.0.5", [t], tmp_path / "o.jsonl", "")
    assert "-no-interactsh" in args and "-iserver" not in args
    assert "dos" in args[args.index("-etags") + 1] and "default-login" in args[args.index("-etags") + 1]
    assert "code" in args[args.index("-ept") + 1] and "headless" in args[args.index("-ept") + 1]
    assert args[args.index("-rate-limit") + 1] == "10"
    args = V.args_nuclei("https://10.0.0.5", [t], tmp_path / "o.jsonl", "https://oast.lab")
    assert args[args.index("-iserver") + 1] == "https://oast.lab" and "-no-interactsh" not in args


@pytest.mark.parametrize("valor,ok", [
    ("", None), ("https://oast.pro", False), ("https://x.oast.live", False), ("https://interact.sh", False),
    ("https://127.0.0.1", True), ("http://localhost:8080", True), ("https://8.8.8.8", False),
    ("https://no-existe.invalid", False), ("https://a.b/../x", False), ("file:///etc/passwd", False),
])
def test_interactsh_solo_propio_e_interno(monkeypatch, valor, ok):
    from opsdeck.core import config
    cfg = config.settings()
    monkeypatch.setattr(V, "settings", lambda: cfg)
    old = cfg.get("verificacion", "interactsh_servidor")
    cfg.set("verificacion", "interactsh_servidor", valor)
    try:
        server, problem = V.interactsh()
    finally:
        cfg.set("verificacion", "interactsh_servidor", old)
    if ok is None:
        assert (server, problem) == ("", "")
    elif ok:
        assert server and not problem
    else:
        assert not server and problem


def test_nuclei_confirma(plantillas, tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "nuclei"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n"
                    "echo '{\"template-id\":\"CVE-2021-44228\",\"matched-at\":\"10.0.0.5:4712\"}' > \"$out\"\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    d = tmp_path / "v"
    d.mkdir()
    c = ctx()
    p = V.run_nuclei(c, "CVE-2021-44228", V.Objetivo("127.0.0.1", 4712), d, False)
    assert p.estado == V.CONFIRMADA and "4712" in p.detalle
    args = (d / "orden_nuclei.txt").read_text().split()
    tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
    assert len(tpls) == 1 and "network/cves/2021" in tpls[0]


def test_nuclei_sin_plantilla_no_concluye(plantillas, tmp_path):
    d = tmp_path / "v"
    d.mkdir()
    if not V.system.has_cmd("nuclei"):
        assert V.run_nuclei(ctx(), "CVE-2099-0001", V.Objetivo("127.0.0.1", 80), d, False).estado == V.NO_CONCLUYENTE
    assert V.plantillas_cve("CVE-2099-0001") == []


# ---------------------------------------------------------------- nmap

def test_scripts_nse_seguros(tmp_path, monkeypatch):
    (tmp_path / "script.db").write_text(
        'Entry { filename = "smb-vuln-ms17-010.nse", categories = { "safe", "vuln", } }\n'
        'Entry { filename = "http-vuln-cve2017-5638.nse", categories = { "vuln", } }\n'
        'Entry { filename = "smb-vuln-ms10-054.nse", categories = { "dos", "intrusive", "vuln", } }\n'
        'Entry { filename = "http-slowloris-check.nse", categories = { "safe", "vuln", } }\n')
    (tmp_path / "smb-vuln-ms17-010.nse").write_text("IDS = {CVE = 'CVE-2017-0143'}")
    (tmp_path / "http-vuln-cve2017-5638.nse").write_text("x")
    (tmp_path / "smb-vuln-ms10-054.nse").write_text("CVE-2017-0143")
    (tmp_path / "http-slowloris-check.nse").write_text("CVE-2017-0143")
    monkeypatch.setattr(V, "NSE_DIRS", (tmp_path,))
    got = dict(V.scripts_cve("CVE-2017-0143"))
    assert got["smb-vuln-ms17-010"] == "" and "dos" in got["smb-vuln-ms10-054"] and got["http-slowloris-check"]
    assert "safe" in dict(V.scripts_cve("CVE-2017-5638"))["http-vuln-cve2017-5638"]
    a = V.args_nmap(V.Objetivo("10.0.0.5", 445), ["smb-vuln-ms17-010"], tmp_path / "x.xml")
    assert a[a.index("--script") + 1] == "smb-vuln-ms17-010" and a[-1] == "10.0.0.5" and "-p" in a


# ---------------------------------------------------------------- de punta a punta

@pytest.fixture
def ssh_falso():
    """Servidor que solo envía un banner SSH (como cualquier sshd al conectar)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
            c.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    t.join(1)
    srv.close()


def test_verificar_cve_por_banner(ssh_falso, monkeypatch, tmp_path):
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    monkeypatch.setattr(osv, "aviso", lambda cve, distro, **k: AVISO_SSH)
    c = ctx()
    assert V.accion_cve(c, {"cve": "CVE-2024-6387", "objetivo": f"127.0.0.1:{ssh_falso}", "motor": "paquetes"})
    sess = results.sessions("verificacion")
    assert len(sess) == 1
    data = json.loads((sess[0] / "veredicto.json").read_text())
    assert data["estado"] == V.CONFIRMADA and "anterior a la corrección" in data["pruebas"][0]["detalle"]
    assert (sess[0] / "banner.txt").read_text().startswith("SSH-2.0-OpenSSH_9.6p1")


def test_fuera_de_alcance_se_bloquea(monkeypatch, tmp_path):
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    c = ctx()
    assert not V.accion_cve(c, {"cve": "CVE-2024-6387", "objetivo": "203.0.113.9:22"})
    assert not results.sessions("verificacion")
    assert any("FUERA del alcance" in line for line in c.out.lines)


def test_hallazgos_de_nuclei_y_escaneo_e_informe(tmp_path, monkeypatch):
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    d = results.new_dir("nuclei", "analisis_x")
    (d / "hallazgos.jsonl").write_text(
        json.dumps({"template-id": "CVE-2023-1234", "matched-at": "https://10.0.0.5:8443/login",
                    "info": {"severity": "high"}}) + "\n"
        + json.dumps({"template-id": "tech-detect", "host": "10.0.0.5", "info": {"severity": "info",
                      "classification": {"cve-id": ["CVE-2022-0001"]}}}) + "\nno es json\n")
    cs = V.candidatos("nuclei", d)
    assert [(c.cve, c.obj.texto) for c in cs] == [("CVE-2023-1234", "https://10.0.0.5:8443"), ("CVE-2022-0001", "10.0.0.5")]
    e = results.new_dir("escaneo", "estandar_10.0.0.0_24")
    (e / "estandar.xml").write_text(
        '<nmaprun args="nmap"><host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" '
        'version="9.6p1 Ubuntu 3ubuntu13.5"/><script id="vulners" output="cpe:/a:openbsd:openssh:9.6p1&#xa;'
        '    CVE-2024-6387  8.1  https://vulners.com/cve/CVE-2024-6387&#xa;    CVE-2023-51385  6.5  x"/></port>'
        '</ports></host></nmaprun>')
    cs = V.candidatos("escaneo", e)
    assert [c.cve for c in cs] == ["CVE-2024-6387", "CVE-2023-51385"]
    assert V.paquete_de_banner(cs[0].banner) == ("openssh", "9.6p1-3ubuntu13.5", "ubuntu")
    from opsdeck.core import informes
    i = results.new_dir("informes", "informe_prueba")
    items, _ = informes.load(Path(__file__).parent / "datos" / "informe_prueba.nessus")
    informes.save(items, i / "hallazgos.json")
    assert all(c.cve.startswith("CVE-") for c in V.candidatos("informes", i))


def test_lote_aislado_y_sin_tocar_el_origen(tmp_path, monkeypatch, ssh_falso):
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    monkeypatch.setattr(osv, "aviso", lambda cve, distro, **k: AVISO_SSH)
    d = results.new_dir("nuclei", "analisis_x")
    src = json.dumps({"template-id": "CVE-2024-6387", "host": f"127.0.0.1:{ssh_falso}", "info": {"severity": "high"}})
    (d / "hallazgos.jsonl").write_text(src + "\n")
    before = sorted(p.name for p in d.iterdir())
    c = ctx()
    assert V.accion_hallazgos(c, {"origen": "nuclei", "sesion": 1, "motor": "paquetes"})
    assert sorted(p.name for p in d.iterdir()) == before and (d / "hallazgos.jsonl").read_text() == src + "\n"
    lote = results.sessions("verificacion")[0]
    assert lote.name.split("_", 2)[2].startswith("lote_nuclei")
    assert (lote / "verificacion.csv").read_text().splitlines()[1].startswith("CONFIRMADA;CVE-2024-6387")
    assert len(list(lote.glob("*/veredicto.json"))) == 1


@pytest.mark.parametrize("carpeta", ["../../etc", "20261125_120000_x/../../y", "/etc", "x"])
def test_carpeta_de_resultados_validada(tmp_path, monkeypatch, carpeta):
    monkeypatch.setattr(results, "ROOT", tmp_path / "res")
    assert V._sesion("nuclei", {"carpeta": carpeta}) is None


def test_modulo_y_acciones():
    from opsdeck.core.catalog import module
    m = module("verificacion")
    assert m and m.full and m.category == "Ciberseguridad"
    assert {a.id for a in m.actions()} == {"cve", "hallazgos", "local", "comprobaciones", "ver"}
    a = m.action("cve")
    assert "Tienes autorización" in a.confirm_text({"cve": "CVE-2024-6387", "objetivo": "10.0.0.5:22", "motor": "auto"})
    assert a.confirm_text({"cve": "CVE-2024-6387", "objetivo": "local"}) == ""


# ---------------------------------------------------------------- actualización

def test_changelog_remoto_limpio_y_solo_lo_nuevo():
    texto = ("# Registro\n\n## 2.6.0 — x\n\n- nuevo \x1b[2J\x07borrado\n\n## 2.5.0 — y\n\n- otra\n\n"
             "## 2.4.3 — z\n\n- vieja\n")
    out = actualizar.extracto_changelog(texto, "2.4.3")
    assert "2.6.0" in out and "2.5.0" in out and "2.4.3" not in out and "vieja" not in out
    assert "\x1b" not in out and "\x07" not in out
    assert len(actualizar.limpiar("a\n" * 50_000)) <= actualizar.CHANGELOG_MAX + 20


def test_orden_de_reinicio_aislada():
    argv = actualizar.argv_reinicio()
    assert argv[1] == "-I" and "from opsdeck.cli import main" in argv[3]
