"""Pruebas del motor de recomendación y de la frescura de fuentes."""

from opsdeck.core import feeds
from opsdeck.core import recomendacion as R


def test_reglas_basicas_y_orden():
    fs = [
        R.Finding("h1", "BAJO", "Faltan cabeceras de seguridad", "cabeceras"),
        R.Finding("h2", "ALTO", "SMBv1 activo", "smbv1"),
        R.Finding("h3", "MEDIO", "Firma SMB no obligatoria", "smb_sin_firma"),
    ]
    recos = R.recommend(fs)
    # ordenadas por severidad (ALTO antes que MEDIO antes que BAJO)
    assert [r.severidad for r in recos] == ["ALTO", "MEDIO", "BAJO"]
    # cada recomendación tiene una acción concreta
    assert all(r.accion for r in recos)


def test_cve_version_marca_busqueda_de_exploit():
    f = R.Finding("10.0.0.9", "CRÍTICO", "Apache 2.4.49", "cve_version",
                  datos={"producto": "Apache", "version": "2.4.49", "cvss": 9.8})
    r = R.recommend([f])[0]
    assert r.buscar_exploit == "Apache 2.4.49"
    assert "parche" in r.accion.lower() or "mitiga" in r.accion.lower()


def test_from_smb():
    rows = [{"ip": "10.0.0.5", "smbv1": True, "firma": "NO requerida"},
            {"ip": "10.0.0.6", "smbv1": False, "firma": "requerida"}]
    fin = R.from_smb(rows)
    tipos = sorted(f.tipo for f in fin)
    assert tipos == ["smb_sin_firma", "smbv1"]
    assert all(f.objetivo == "10.0.0.5" for f in fin)


def test_from_web_clasifica_hallazgos():
    result = {"url": "https://x", "hallazgos": [
        ("MEDIO", "Acepta versiones obsoletas: TLS 1.0"),
        ("ALTO", "Certificado CADUCADO el 2026-01-01"),
        ("BAJO", "Faltan cabeceras de seguridad: content-security-policy"),
    ]}
    tipos = {f.tipo for f in R.from_web(result)}
    assert tipos == {"tls_obsoleto", "cert_caducado", "cabeceras"}


def test_from_nuclei_descarta_info_y_bajo():
    findings = [
        {"info": {"severity": "critical", "name": "RCE"}, "matched-at": "http://x", "template-id": "cve-x"},
        {"info": {"severity": "info", "name": "ruido"}, "host": "x", "template-id": "tech"},
    ]
    fin = R.from_nuclei(findings)
    assert len(fin) == 1 and fin[0].severidad == "CRÍTICO"


def test_dedup():
    f = R.Finding("h", "ALTO", "SMBv1 activo", "smbv1")
    assert len(R.recommend([f, f])) == 1


def test_public_exploit_sin_searchsploit(monkeypatch):
    monkeypatch.setattr(R.system, "has_cmd", lambda n: False)
    assert R.public_exploit("Apache 2.4.49") is None


def test_feed_vieja(tmp_path, monkeypatch):
    f = feeds.Feed("x", True, 30)
    assert f.vieja
    assert not feeds.Feed("x", True, 1).vieja
    assert not feeds.Feed("x", False).vieja


def test_feeds_status_tres_fuentes():
    fs = feeds.status()
    assert {f.nombre for f in fs} == {"Plantillas de nuclei", "Base de exploit-db", "Listas de paquetes (apt)"}


def test_warn_if_stale(monkeypatch):
    msgs = []

    class Out:
        def warn(self, m): msgs.append(("warn", m))
        def line(self, m=""): msgs.append(("line", m))

    class C:
        out = Out()

    monkeypatch.setattr(feeds, "status", lambda: [feeds.Feed("Plantillas de nuclei", True, 40)])
    feeds.warn_if_stale(C())
    assert any(k == "warn" for k, _ in msgs)
