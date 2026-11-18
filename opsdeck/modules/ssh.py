"""Auditoría SSH de equipos remotos: algoritmos débiles, Terrapin, claves de equipo, autenticación por
contraseña y versión, que es lo que reportan Nessus y OpenVAS sobre SSH.

Motor: nmap (ssh2-enum-algos, ssh-hostkey, ssh-auth-methods) y, si está instalado, ssh-audit para el
detalle y las CVE conocidas de la versión. No intenta iniciar sesión."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from ..core import audit, nmapxml, recomendacion, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from ..core.recomendacion import Finding
from .escaneo import _subnets, ultimo
from .tls import _split_targets

WEAK_KEX = re.compile(r"(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|"
                      r"gss-.*-sha1-|rsa1024-sha1|ecdh-sha2-1\.3\.132)")
WEAK_ENC = re.compile(r"(-cbc$|-cbc@|^arcfour|^3des|^blowfish|^cast128|^none$|^des-|^rijndael)")
WEAK_MAC = re.compile(r"(md5|-96|umac-64@|umac-64-etm@|ripemd|^none$)")
SHA1_MAC = re.compile(r"^hmac-sha1(-etm@openssh\.com)?$")
WEAK_HOSTKEY = re.compile(r"^(ssh-dss|ssh-rsa-cert-v00|x509v3-sign-dss)")
SSH_PORTS = [22, 2222, 22222]


def parse_algos(text: str) -> dict:
    out: dict = defaultdict(list)
    sect = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^(\w+): \(\d+\)$", line)
        if m:
            sect = m.group(1)
            continue
        if sect and line:
            out[sect].append(line)
    return dict(out)


def analyze_port(ip: str, p: nmapxml.Port, skip_sha1: bool = False) -> list[Finding]:
    obj = f"{ip}:{p.port}"
    a = parse_algos(p.scripts.get("ssh2-enum-algos", ""))
    out: list[Finding] = []

    def add(sev, title, tipo, **d):
        out.append(Finding(obj, sev, title, tipo, datos={"puerto": p.port, **d}))

    kex, enc, mac = a.get("kex_algorithms", []), a.get("encryption_algorithms", []), a.get("mac_algorithms", [])
    hk = a.get("server_host_key_algorithms", [])
    weak = [k for k in kex if WEAK_KEX.search(k)]
    if weak:
        add("BAJO", f"Intercambio de claves débil (SHA-1/grupo corto): {', '.join(weak)}", "ssh_kex", algoritmos=weak)
    weak = [e for e in enc if WEAK_ENC.search(e)]
    if weak:
        cbc = [e for e in weak if "cbc" in e]
        add("MEDIO" if len(weak) > len(cbc) else "BAJO",
            f"Cifrados débiles{' (CBC)' if cbc else ''}: {', '.join(weak)}", "ssh_cifrado", algoritmos=weak)
    weak = [m for m in mac if WEAK_MAC.search(m)]
    if not skip_sha1:
        weak += [m for m in mac if SHA1_MAC.search(m)]
    if weak:
        add("BAJO", f"Algoritmos MAC débiles: {', '.join(weak)}", "ssh_mac", algoritmos=weak)
    weak = [h for h in hk if WEAK_HOSTKEY.search(h)]
    for line in p.scripts.get("ssh-hostkey", "").splitlines():
        m = re.match(r"\s*(\d+) \S+ \((RSA|DSA)\)", line)
        if m and (m.group(2) == "DSA" or int(m.group(1)) < 2048):
            weak.append(f"{m.group(2)} de {m.group(1)} bits")
    if weak:
        add("MEDIO", f"Claves o algoritmos de equipo débiles: {', '.join(weak)}", "ssh_hostkey")
    if kex and "kex-strict-s-v00@openssh.com" not in kex:
        etm_cbc = any(m.endswith("-etm@openssh.com") for m in mac) and any("cbc" in e for e in enc)
        if "chacha20-poly1305@openssh.com" in enc or etm_cbc:
            add("MEDIO", "Vulnerable a Terrapin (CVE-2023-48795): sin «strict kex»", "ssh_terrapin")
    methods = p.scripts.get("ssh-auth-methods", "")
    if re.search(r"^\s*(password|keyboard-interactive)\s*$", methods, re.M):
        add("BAJO", "Acepta autenticación por contraseña (expuesta a fuerza bruta)", "ssh_password")
    if "SSH-1" in p.scripts.get("sshv1", "") or "Server supports SSHv1" in p.scripts.get("sshv1", ""):
        add("ALTO", "Admite el protocolo SSH 1", "ssh_v1")
    prod = " ".join(x for x in (p.product, p.version) if x).strip()
    if prod:
        add("INFO", f"Versión: {prod}", "ssh_version", exploit=prod)
    return out


def ssh_audit(ctx: Context, host: str, port: int, d: Path) -> list[Finding]:
    """CVE conocidas de la versión según ssh-audit (base local de la herramienta)."""
    r = system.run(["ssh-audit", "-j", "-p", str(port), host], timeout=60)
    try:
        data = json.loads(r.out)
    except (json.JSONDecodeError, ValueError):
        return []
    results.write(d / f"ssh-audit_{host}_{port}.json", r.out)
    out = []
    for c in data.get("cves", []) or []:
        cvss = float(c.get("cvssv2", 0) or 0)
        out.append(Finding(f"{host}:{port}", recomendacion._sev_cvss(cvss) if cvss else "MEDIO",
                           f"{c.get('name', 'CVE')}: {c.get('description', '')[:80]}", "ssh_version",
                           datos={"puerto": port, "exploit": c.get("name", "")}))
    return out


def run_checks(ctx: Context, groups: dict, v: dict, d: Path) -> tuple[list[Finding], list]:
    by_ports: dict = defaultdict(list)
    for host, ports in groups.items():
        by_ports[tuple(sorted(ports or SSH_PORTS))].append(host)
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN)
    if err:
        ctx.out.error(err)
        return [], []
    findings, rows = [], []
    user = (v.get("usuario") or "root").strip()
    if not re.match(r"^[A-Za-z0-9._-]{1,32}$", user):
        ctx.out.error("Usuario no válido")
        return [], []
    for i, (ports, hosts) in enumerate(by_ports.items(), 1):
        out = d / f"ssh_{i}"
        args = ["nmap", "-Pn", "-sV", "--version-light", "-p", ",".join(map(str, ports)), "--open",
                "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1", "--script-args", f"ssh.user={user}",
                "-oA", str(out), *extra, *hosts]
        tooling.show_cmd(ctx, args)
        stream(ctx, args, accion="ssh_auditoria", objetivo=" ".join(hosts), keep=6)
        for h in nmapxml.parse(out.with_suffix(".xml")).up():
            for p in h.open_ports():
                if "ssh2-enum-algos" not in p.scripts:
                    continue
                f = analyze_port(h.ip, p, skip_sha1=bool(v.get("sin_sha1")))
                if v.get("ssh_audit", True) and system.has_cmd("ssh-audit"):
                    f += ssh_audit(ctx, h.ip, p.port, d)
                findings += f
                real = [x for x in f if x.severidad != "INFO"]
                worst = min((x.severidad for x in real), key=lambda s: recomendacion.ORDEN.get(s, 9), default="ok")
                rows.append([f"{h.ip}:{p.port}", " ".join(x for x in (p.product, p.version) if x)[:30] or "?",
                             "sí" if any(x.tipo == "ssh_password" for x in f) else "no",
                             "SÍ" if any(x.tipo == "ssh_terrapin" for x in f) else "no", str(len(real)), worst])
    return findings, rows


def revisar(ctx: Context, v: dict) -> bool:
    text = (v.get("objetivo") or "").strip()
    if text:
        groups, bad = _split_targets(text)
        if bad:
            ctx.out.error("Objetivos no válidos: " + ", ".join(bad))
            return False
        if not scope.gate(ctx, " ".join(groups), v, "ssh"):
            return False
        label = text.replace("/", "_")[:40]
    else:
        scan = ultimo(ctx)
        if scan is None:
            return False
        groups = defaultdict(set)
        for h in scan.up():
            for p in h.open_ports():
                if p.service == "ssh" or p.port == 22:
                    groups[h.ip].add(p.port)
        groups, label = dict(groups), "ultimo_escaneo"
        if not groups:
            ctx.out.info("El último escaneo no tiene servicios SSH.")
            return True
    ports = (v.get("puertos") or "").replace(" ", "")
    if ports:
        if not re.match(r"^[0-9,]+$", ports):
            ctx.out.error("Puertos no válidos (ej.: 22,2222)")
            return False
        groups = {h: set(map(int, filter(None, ports.split(",")))) for h in groups}
    d = results.new_dir("ssh", label)
    findings, rows = run_checks(ctx, groups, v, d)
    if not rows:
        ctx.out.info("No se encontró ningún servicio SSH en esos objetivos.")
        return True
    ctx.out.title(f"{len(rows)} servicios SSH")
    ctx.out.table(["Servicio", "Versión", "Contraseña", "Terrapin", "Hallazgos", "Peor"], rows)
    real = [f for f in findings if f.severidad != "INFO"]
    if real:
        ctx.out.title("Hallazgos")
        for f in sorted(real, key=lambda f: (recomendacion.ORDEN.get(f.severidad, 9), f.objetivo)):
            ctx.out.check(False, f"[{f.severidad}] {f.objetivo}  {f.titulo[:120]}")
    else:
        ctx.out.ok("Sin algoritmos débiles ni problemas de configuración visibles desde la red.")
    results.write(d / "hallazgos.json", recomendacion.to_json(findings))
    audit.record("ssh_resultado", label, "OK", f"servicios={len(rows)} hallazgos={len(real)}")
    if not system.has_cmd("ssh-audit"):
        ctx.out.info("Con ssh-audit instalado (Catálogo › opcionales) se añaden las CVE conocidas de cada versión.")
    ctx.out.info("Configuración recomendada para sshd: ssh-audit.com/hardening_guides o «Bastionado (Lynis) › SSH».")
    recomendacion.render(ctx, findings)
    return True


def detalle(ctx: Context, v: dict) -> bool:
    host = (v.get("equipo") or "").strip()
    groups, bad = _split_targets(host)
    if bad or len(groups) != 1:
        ctx.out.error("Indica un solo equipo (equipo o equipo:puerto)")
        return False
    if not scope.gate(ctx, " ".join(groups), v, "ssh"):
        return False
    h, ports = next(iter(groups.items()))
    port = next(iter(ports), 22)
    d = results.new_dir("ssh", f"ssh-audit_{h}")
    args = ["ssh-audit", "-p", str(port), "--no-colors"] + (["-l", v["nivel"]] if v.get("nivel") else []) + [h]
    rc, _ = stream(ctx, args, accion="ssh_audit", objetivo=f"{h}:{port}", save_to=d / "ssh-audit.txt",
                   ok_rc=(0, 1, 2, 3))
    ctx.out.info(f"Guardado en {d}")
    return rc in (0, 1, 2, 3)


class Ssh(Module):
    full = True
    id = "ssh"
    name = "Auditoría SSH"
    category = "Ciberseguridad"
    summary = "Algoritmos débiles, Terrapin, claves de equipo, contraseña y versión de servidores SSH remotos"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    optional = [cmd("ssh-audit", debian="ssh-audit", arch="ssh-audit", label="ssh-audit")]
    help = """\
# Auditoría SSH

> Solo contra sistemas propios o con autorización por escrito. No intenta iniciar sesión.

**Revisar SSH** (un equipo, una red o todos los SSH del último escaneo) detecta lo que reportan
Nessus y OpenVAS sobre SSH:

- **Intercambio de claves débil** (SHA-1, grupo 1) · «SSH Weak Key Exchange Algorithms»
- **Cifrados CBC, 3DES, arcfour** · «SSH Server CBC Mode Ciphers», «Weak Encryption Algorithms»
- **MAC débiles** (MD5, -96, umac-64, SHA-1) · «Weak MAC Algorithm(s)», «SHA-1 HMAC»
- **Claves de equipo débiles** (DSA, RSA < 2048) · «Weak Host Key Algorithm(s)»
- **Terrapin** (CVE-2023-48795) · «SSH Terrapin Prefix Truncation Weakness»
- **Acepta contraseña** · «SSH Password Authentication Accepted»
- **Versión** del servidor (para buscar CVE y exploits públicos). Con **ssh-audit** instalado se
  añaden las CVE conocidas de esa versión.

Recuerda que en Debian/Ubuntu/RHEL la versión que anuncia OpenSSH no refleja los parches de la
distribución: confirma con «Análisis dirigido» de nuclei o con el gestor de paquetes del equipo.

**Detalle con ssh-audit**: informe completo de un servidor con recomendaciones línea a línea.

**Opciones avanzadas**: puertos, usuario con el que se consultan los métodos de autenticación (no se
inicia sesión), no marcar HMAC-SHA1 como débil, y opciones de nmap.
"""

    def actions(self):
        A = dict(required=False, advanced=True)
        ok = scope.ok_param()
        return [
            Action("revisar", "Revisar SSH", revisar, params=[
                Param("objetivo", "Objetivo (vacío = SSH del último escaneo)", required=False, suggest=_subnets,
                      help="equipo, equipo:puerto, red, varios separados por espacio o fichero"), ok,
                Param("puertos", "Puertos SSH", **A, help="Ej.: 22,2222 (por defecto 22, 2222, 22222)"),
                Param("usuario", "Usuario para consultar los métodos de autenticación", "text", "root", **A,
                      help="No se inicia sesión: solo se pregunta qué métodos admite el servidor para ese usuario."),
                Param("sin_sha1", "No marcar HMAC-SHA1 como débil", "bool", False, **A),
                Param("ssh_audit", "Añadir CVE con ssh-audit si está instalado", "bool", True, **A),
                tooling.p_extra("nmap", "-T3")]),
            Action("detalle", "Detalle de un servidor (ssh-audit)", detalle, requires=[cmd("ssh-audit")], params=[
                Param("equipo", "Equipo (o equipo:puerto)"), ok,
                Param("nivel", "Mostrar desde", "choice", "", choices=[("", "Todo"), ("info", "Información"),
                                                                       ("warn", "Avisos"), ("fail", "Fallos")], **A)]),
        ]
