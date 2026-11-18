"""Pruebas de la ampliación 2.4: opciones avanzadas, nuevos módulos (TLS, SSH, servicios expuestos,
informes) y arreglos (alcance con URL, escaneos de descubrimiento, opciones «Todas»)."""
import os
from pathlib import Path

os.environ.setdefault("OPSDECK_DATA", "/tmp/od/data")
os.environ.setdefault("OPSDECK_LOG", "/tmp/od/log")
os.environ.setdefault("OPSDECK_CONF", "/tmp/od/od.conf")

from opsdeck.core import informes, nmapxml, scope, tooling  # noqa: E402
from opsdeck.core.catalog import Action, Param  # noqa: E402
from opsdeck.core.ops import check_params  # noqa: E402

DATOS = Path(__file__).parent / "datos"


# ---------------------------------------------------------------- núcleo

def test_alcance_entiende_urls_y_puertos():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/24")]
    assert scope.host_of("https://10.0.0.5:8443/login?x=1") == "10.0.0.5"
    assert scope.host_of("10.0.0.5:22") == "10.0.0.5"
    assert scope.host_of("[fe80::1]:443") == "fe80::1"
    assert scope.host_of("https://usuario:clave@10.0.0.7/") == "10.0.0.7"
    assert scope.host_of("10.0.0.0/24") == "10.0.0.0/24"
    r = scope.classify("https://10.0.0.5:8443 10.0.0.9:22 http://10.0.1.1", nets)
    assert r.dentro == ["10.0.0.5", "10.0.0.9"] and r.fuera == ["10.0.1.1"]


def test_opcion_vacia_de_una_lista_es_valida():
    a = Action("x", "x", lambda c, v: True, params=[
        Param("grupo", "Alcance", "choice", "", choices=[("", "Todas"), ("ssh", "SSH")])])
    assert check_params(a, {"grupo": ""}) is None
    assert check_params(a, {"grupo": "ssh"}) is None
    assert check_params(a, {"grupo": "otro"})


def test_opciones_extra_se_filtran():
    args, err = tooling.extra_args("--reason -sV --data-length 25")
    assert not err and args == ["--reason", "-sV", "--data-length", "25"]
    for bad in ("-oX /tmp/x", "-oA x", "-iL lista", "--output=x", "-ofichero"):
        assert tooling.extra_args(bad)[1], bad
    assert tooling.extra_args("'sin cerrar")[1]
    assert tooling.headers("Cookie: a=1; X-Prueba: 2")[0] == ["Cookie: a=1", "X-Prueba: 2"]
    assert tooling.headers("sin dos puntos")[1]
    assert tooling.proxy("http://127.0.0.1:8080")[0] and tooling.proxy("ftp://x")[1]
    assert tooling.int_in("abc", 5, 1, 10) == 5 and tooling.int_in("99", 5, 1, 10) == 10


def test_parametros_avanzados_separados():
    from opsdeck.core.catalog import module
    a = module("escaneo").action("escanear")
    assert {p.name for p in a.basic_params()} >= {"objetivo", "perfil"}
    assert {"puertos", "tiempo", "sin_ping", "scripts", "extra"} <= {p.name for p in a.advanced_params()}


def test_nmap_avanzado():
    from opsdeck.modules import escaneo as e

    class O:
        msgs = []

        def error(self, m):
            self.msgs.append(m)

    class C:
        out = O()

    args = e.advanced(C(), {"puertos": "22,80", "tiempo": "T2", "sin_ping": True, "scripts": "ssl-enum-ciphers",
                            "extra": "--reason"}, e.PROFILES["estandar"][1])
    assert "-p" in args and args[args.index("-p") + 1] == "22,80" and "--top-ports" not in args
    assert "-T2" in args and "-T4" not in args and "-Pn" in args and "--reason" in args
    assert args[args.index("--script") + 1] == "ssl-enum-ciphers"
    assert e.advanced(C(), {"puertos": "-"}, e.PROFILES["rapido"][1])[-1] == "-p-"
    assert e.advanced(C(), {"extra": "-oN x"}, e.PROFILES["rapido"][1]) is None
    assert e.advanced(C(), {"puertos": "22;rm"}, e.PROFILES["rapido"][1]) is None


def test_escaneos_de_descubrimiento_no_cuentan_como_ultimo(tmp_path, monkeypatch):
    from opsdeck.core import results
    from opsdeck.modules import escaneo
    monkeypatch.setattr(results, "ROOT", tmp_path)
    a = tmp_path / "escaneo" / "20260101_100000_estandar_x"
    b = tmp_path / "escaneo" / "20260101_110000_descubrimiento_x"
    for d, f in ((a, "estandar.xml"), (b, "descubrimiento.xml")):
        d.mkdir(parents=True)
        (d / f).write_text("<nmaprun/>")
    assert escaneo.escaneos() == [a / "estandar.xml"]
    assert escaneo.escaneos(con_puertos=False)[0] == b / "descubrimiento.xml"


# ---------------------------------------------------------------- TLS

ENUM = """
  TLSv1.0:
    ciphers:
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
      TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
      TLS_ECDH_anon_WITH_AES_128_CBC_SHA (ecdh_x25519) - F
    compressors:
      NULL
    cipher preference: server
    warnings:
      64-bit block cipher 3DES vulnerable to SWEET32 attack
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
    cipher preference: server
  least strength: F"""
CERT = """Subject: commonName=srv.ejemplo.local
Subject Alternative Name: DNS:srv.ejemplo.local, DNS:www.ejemplo.local
Issuer: commonName=srv.ejemplo.local
Public Key type: rsa
Public Key bits: 1024
Signature Algorithm: sha1WithRSAEncryption
Not valid before: 2020-01-01T00:00:00
Not valid after:  2021-01-01T00:00:00"""


def test_tls_interpreta_nmap():
    from opsdeck.modules import tls
    p = nmapxml.Port(443, "tcp", "open", "https", scripts={"ssl-enum-ciphers": ENUM, "ssl-cert": CERT})
    f = tls.analyze_port("10.0.0.5", "otro.ejemplo.local", p, check_trust=False)
    tipos = {x.tipo for x in f}
    assert {"tls_obsoleto", "tls_sweet32", "tls_rc4", "tls_anon", "tls_firma_debil", "tls_clave_corta",
            "cert_caducado", "cert_autofirmado", "cert_nombre"} <= tipos
    assert tls.name_matches("www.ejemplo.local", tls.parse_cert(CERT))
    assert not tls.name_matches("ejemplo.local", tls.parse_cert(CERT))
    assert tls.parse_cert("") == {}
    groups, bad = tls._split_targets("10.0.0.1:443 https://10.0.0.2:8443/x srv.ejemplo.local 10.0.0.0/24 mal;nombre")
    assert groups["10.0.0.1"] == {443} and groups["10.0.0.2"] == {8443} and groups["srv.ejemplo.local"] == set()
    assert bad == ["mal;nombre"]


# ---------------------------------------------------------------- SSH

ALGOS = """
  kex_algorithms: (3)
      curve25519-sha256
      diffie-hellman-group1-sha1
      diffie-hellman-group-exchange-sha1
  server_host_key_algorithms: (2)
      ssh-rsa
      ssh-dss
  encryption_algorithms: (3)
      chacha20-poly1305@openssh.com
      aes128-cbc
      3des-cbc
  mac_algorithms: (3)
      hmac-sha2-256-etm@openssh.com
      hmac-md5
      hmac-sha1"""


def test_ssh_interpreta_nmap():
    from opsdeck.modules import ssh
    p = nmapxml.Port(22, "tcp", "open", "ssh", "OpenSSH", "7.4", scripts={
        "ssh2-enum-algos": ALGOS, "ssh-auth-methods": "  Supported authentication methods: \n    publickey\n    password",
        "ssh-hostkey": "  1024 aa:bb (DSA)\n  2048 cc:dd (RSA)"})
    f = ssh.analyze_port("10.0.0.5", p)
    tipos = {x.tipo for x in f}
    assert {"ssh_kex", "ssh_cifrado", "ssh_mac", "ssh_hostkey", "ssh_terrapin", "ssh_password", "ssh_version"} <= tipos
    ok = nmapxml.Port(22, "tcp", "open", "ssh", scripts={"ssh2-enum-algos": ALGOS.replace(
        "curve25519-sha256", "curve25519-sha256\n      kex-strict-s-v00@openssh.com")})
    assert "ssh_terrapin" not in {x.tipo for x in ssh.analyze_port("10.0.0.5", ok)}


# ---------------------------------------------------------------- servicios expuestos

def test_exposicion_interpreta_scripts():
    from opsdeck.modules import exposicion as ex
    cases = [
        ({"rdp-enum-encryption": "  Security layer\n    CredSSP (NLA): SUCCESS\n    Native RDP: SUCCESS\n"
                                 "  RDP Encryption level: Client Compatible\n    40-bit RC4: SUCCESS"}, 3389,
         {"rdp_nla", "rdp_cifrado"}),
        ({"rdp-enum-encryption": "  Security layer\n    CredSSP (NLA): SUCCESS\n    CredSSP with Early User Auth: SUCCESS"},
         3389, set()),
        ({"iscsi-info": "  iqn.2006-01.com.ejemplo:disco1:\n    Address: 10.0.0.5:3260,1\n    Authentication: NOT required"},
         3260, {"iscsi_sin_auth"}),
        ({"snmp-sysdescr": "Linux equipo 5.10"}, 161, {"snmp_comunidad"}),
        ({"nfs-showmount": "  /srv/datos *\n  /home 10.0.0.0/24"}, 2049, {"nfs_export"}),
        ({"redis-info": "  Version: 7.0.15\n  Operating System: Linux"}, 6379, {"bd_sin_auth"}),
        ({"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"}, 21, {"ftp_anonimo"}),
        ({"docker-version": "  Version: 24.0.5"}, 2375, {"docker_api"}),
        ({"vnc-info": "  Protocol version: 3.8\n  Security types: \n    None (1)"}, 5900, {"vnc_sin_auth"}),
        ({"ipmi-cipher-zero": "  VULNERABLE:\n  IPMI 2.0 RAKP Cipher Zero"}, 623, {"ipmi_cifrado0"}),
        ({"ntp-monlist": "  Target is synchronised with 10.0.0.1\n  Public Clients (3)"}, 123, {"ntp_monlist"}),
        ({"dns-recursion": "Recursion appears to be enabled"}, 53, {"dns_recursion"}),
        ({"smtp-commands": "mail.ejemplo.local, PIPELINING, VRFY, ETRN"}, 25, {"smtp_vrfy"}),
    ]
    for scripts, port, expected in cases:
        p = nmapxml.Port(port, "udp" if port in (161, 623, 123) else "tcp", "open", "", scripts=scripts)
        got = {f.tipo for f in ex.analyze("10.0.0.5", p) if f.severidad != "INFO"}
        assert got == expected, (scripts, got)
    args, scripts = ex.build_nmap({"udp": False, "dominio": "ejemplo.local"}, [ex.BY_ID["dns"], ex.BY_ID["rdp"]])
    assert "-sU" not in args and "dns-zone-transfer" in scripts
    assert "dns-zone-transfer.domain=ejemplo.local" in args[args.index("--script-args") + 1]
    args, scripts = ex.build_nmap({"credenciales": True}, ex.CHECKS)
    assert "mysql-empty-password" in scripts and "snmp-brute" in scripts and "-sU" in args
    assert "smtp-open-relay" not in ex.build_nmap({}, ex.CHECKS)[1]


def test_recomendaciones_de_tipos_nuevos():
    from opsdeck.core import recomendacion as r
    tipos = ["tls_sweet32", "ssh_terrapin", "rdp_nla", "iscsi_sin_auth", "icmp_timestamp", "difusion", "cookies"]
    recos = r.recommend([r.Finding("10.0.0.5", "MEDIO", t, t) for t in tipos])
    assert len(recos) == len(tipos) and all(x.accion for x in recos)
    js = r.to_json([r.Finding("10.0.0.5", "ALTO", "x", "tls_ssl", datos={"puerto": 443})])
    assert r.from_json(js)[0].datos["puerto"] == 443


# ---------------------------------------------------------------- nuclei

def test_nuclei_opciones_y_etiquetas(tmp_path):
    from opsdeck.modules import nuclei

    class O:
        def error(self, m):
            raise AssertionError(m)

    class C:
        out = O()

    args = nuclei.build_args(C(), {"etiquetas": "cve", "excluir_etiquetas": "dos", "velocidad": "20", "hilos": "5",
                                    "protocolo": "http", "cabeceras": "Cookie: s=1", "proxy": "http://127.0.0.1:8080",
                                    "sin_interactsh": True, "extra": "-mhe 3"},
                             tmp_path / "t", tmp_path / "o", tags="grafana", severity="critical")
    j = " ".join(args)
    assert "-tags cve,grafana" in j and "-etags dos" in j and "-rate-limit 20" in j and "-c 5" in j
    assert "-type http" in j and "-H Cookie: s=1" in j and "-proxy http://127.0.0.1:8080" in j
    assert "-no-interactsh" in args and "-severity critical" in j and args[-2:] == ["-mhe", "3"]
    scan = nmapxml.Scan(Path("x"), hosts=[nmapxml.Host("10.0.0.5", ports=[
        nmapxml.Port(3000, "tcp", "open", "http", "Grafana http"), nmapxml.Port(22, "tcp", "open", "ssh", "OpenSSH", "8.2")])])
    tags = nuclei.tags_from_scan(scan)
    assert "grafana" in tags and "openssh" in tags
    assert nuclei.targets_from_scan(scan) == ["http://10.0.0.5:3000", "10.0.0.5:22"]


# ---------------------------------------------------------------- informes

def test_informe_nessus():
    items, fmt = informes.load(DATOS / "informe_prueba.nessus")
    assert fmt == "nessus" and len(items) == 9
    sw = next(i for i in items if "SWEET32" in i.nombre)
    assert sw.puerto == 8443 and sw.severidad == "ALTO"
    checks = {i.nombre: informes.classify(i)[0] for i in items}
    assert checks["SMB Signing not required"] == "smb"
    assert checks["SSH Server CBC Mode Ciphers Enabled"] == "ssh"
    assert checks["ICMP Timestamp Request Remote Date Disclosure"] == "icmp"
    assert checks["Redis Server Unprotected by Password Authentication"] == "exposicion:redis"
    assert checks["OpenSSH < 99.0 Multiple Vulnerabilities"] == "nuclei"


def test_informe_openvas_xml_y_csv():
    xml = """<report><report><results>
      <result><host>10.0.0.5</host><port>3389/tcp</port><threat>Medium</threat><severity>5.0</severity>
        <nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection</name>
        <refs><ref type="cve" id="CVE-2011-3389"/></refs></nvt></result>
      <result><host>10.0.0.6</host><port>general/tcp</port><threat>Low</threat><severity>2.6</severity>
        <nvt oid="1.3.6.1.4.1.25623.1.0.2"><name>TCP Timestamps Information Disclosure</name></nvt></result>
    </results></report></report>"""
    root = informes.ET.fromstring(xml)
    items = informes.parse_openvas_xml(root)
    assert items[0].puerto == 3389 and items[0].cves == ["CVE-2011-3389"] and items[0].severidad == "MEDIO"
    assert items[1].puerto is None and informes.classify(items[1])[0] == "tcp"
    csv_text = ('"Plugin ID","CVE","CVSS v2.0 Base Score","Risk","Host","Protocol","Port","Name"\n'
                '"57608","","5.0","Medium","10.0.0.7","tcp","445","SMB Signing not required"\n')
    it = informes.parse_csv(csv_text)[0]
    assert it.host == "10.0.0.7" and it.puerto == 445 and it.severidad == "MEDIO"


def test_informe_desde_texto_de_pdf():
    plugin = ("326244 (2) - OpenSSH < 10.4 Multiple Vulnerabilities                    11\n"
              "Risk Factor\n\nCritical\n\nPlugin Output\n\n10.0.0.8 (tcp/22/ssh)\n\n  Installed version : 8.2\n\n"
              "10.0.0.9 (tcp/2222/ssh)\n\n57608 (1) - SMB Signing not required    20\nRisk Factor\n\nMedium\n"
              "10.0.0.8 (tcp/445/cifs)\n")
    items = informes.parse_pdf_text(plugin)
    assert [(i.host, i.puerto, i.severidad) for i in items] == [
        ("10.0.0.8", 22, "CRÍTICO"), ("10.0.0.9", 2222, "CRÍTICO"), ("10.0.0.8", 445, "MEDIO")]
    host = ("                              10.0.0.8\n"
            "        CRITICAL                HIGH                 MEDIUM                  LOW                  INFO\n"
            "    MEDIUM         6.5    -            -            57582     SSL Self-Signed Certificate\n"
            "    MEDIUM         5.3    -            -            57608\n"
            "    MEDIUM                                                     SMB Signing not required\n")
    items = informes.parse_pdf_text(host)
    assert [(i.id, i.nombre) for i in items] == [("57582", "SSL Self-Signed Certificate"),
                                                  ("57608", "SMB Signing not required")]
    ov = ("2 Results per Host\n2.1      10.0.0.8\n2.1.1        Medium 443/tcp\n    Medium (CVSS: 5.0)\n"
          "    NVT: SSL/TLS: Certi\x1ccate Expired\n2.1.2        Low general/icmp\n    Low (CVSS: 2.1)\n"
          "    NVT: ICMP Timestamp Reply Information Disclosure\n")
    items = informes.parse_pdf_text(ov)
    assert items[0].nombre == "SSL/TLS: Certificate Expired" and items[0].puerto == 443
    assert informes.classify(items[0])[0] == "tls" and informes.classify(items[1])[0] == "icmp"


# ---------------------------------------------------------------- instalación de opcionales

def test_herramientas_opcionales(monkeypatch):
    from opsdeck.core import catalog, installer, system
    from opsdeck.modules.tls import Tls
    m = Tls()
    monkeypatch.setattr(system, "has_cmd", lambda c: c == "nmap")
    monkeypatch.setattr(system, "os_family", lambda: "debian")
    monkeypatch.setattr(catalog.edition, "allowed_full", lambda: (True, ""))
    assert [r.value for r in m.missing_optional()] == ["sslscan"]
    assert installer.wanted_packages(m) == [] and installer.wanted_packages(m, opcionales=True) == ["sslscan"]
