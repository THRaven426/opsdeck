"""SMB y Windows: SMBv1, firma SMB (riesgo de relay NTLM), sistema operativo y recursos compartidos.

Funciona solo con nmap (scripts NSE). Si están instalados, usa smbclient para listar recursos con
credenciales y netexec para un barrido rápido. Solo contra sistemas propios o autorizados."""

from __future__ import annotations

import os
import re
import tempfile

from ..core import audit, nmapxml, recomendacion, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, any_cmd, cmd
from ..core.ops import stream
from .escaneo import _subnets, _targets


def analyze_host(h: nmapxml.Host) -> dict:
    proto = h.scripts.get("smb-protocols", "")
    sec2 = h.scripts.get("smb2-security-mode", "")
    sec1 = h.scripts.get("smb-security-mode", "")
    osd = h.scripts.get("smb-os-discovery", "")
    smbv1 = "SMBv1" in proto or "NT LM 0.12" in proto
    if sec2:
        signing = "requerida" if ("required" in sec2 and "not required" not in sec2) else "NO requerida"
    elif sec1:
        if re.search(r"message_signing: required", sec1):
            signing = "requerida"
        elif re.search(r"message_signing: (disabled|supported)", sec1):
            signing = "NO requerida"
        else:
            signing = "?"
    else:
        signing = "?"
    m = re.search(r"OS: (.+)", osd)
    name = re.search(r"Computer name: (\S+)", osd) or re.search(r"NetBIOS computer name: (\S+)", osd)
    return {"ip": h.ip, "nombre": (name.group(1) if name else h.name) or "-", "so": m.group(1).strip() if m else h.os or "-",
            "smbv1": smbv1, "firma": signing, "abierto": any(p.port == 445 for p in h.open_ports())}


def seguridad(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "smb_seguridad"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    d = results.new_dir("smb", v["objetivo"].replace("/", "_"))
    out = d / "smb"
    scripts = "smb-protocols,smb2-security-mode,smb-security-mode,smb-os-discovery"
    if v.get("vulns"):
        scripts += ",smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-double-pulsar-backdoor"
    if v.get("scripts") and re.match(r"^[A-Za-z0-9_,.-]+$", v["scripts"]):
        scripts += "," + v["scripts"]
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN)
    if err:
        ctx.out.error(err)
        return False
    ports = tooling.csv(v.get("puertos") or "139,445") or "139,445"
    args = ["nmap", "-Pn", "-p", ports, "--open", "--script", scripts, "-" + (v.get("tiempo") or "T4"),
            "-oA", str(out), *extra, *t]
    tooling.show_cmd(ctx, args)
    rc, _ = stream(ctx, args, accion="smb_seguridad", objetivo=" ".join(t), keep=10)
    scan = nmapxml.parse(out.with_suffix(".xml"))
    rows = [analyze_host(h) for h in scan.up()]
    rows = [r for r in rows if r["abierto"]]
    if not rows:
        ctx.out.info("Ningún equipo con SMB (445) accesible.")
        return rc == 0
    ctx.out.title(f"{len(rows)} equipos con SMB")
    ctx.out.table(["IP", "Nombre", "Sistema", "SMBv1", "Firma SMB"],
                  [[r["ip"], r["nombre"], r["so"][:40], "SÍ" if r["smbv1"] else "no", r["firma"]] for r in rows])
    v1 = [r["ip"] for r in rows if r["smbv1"]]
    nosign = [r["ip"] for r in rows if r["firma"] == "NO requerida"]
    if v1:
        ctx.out.check(False, f"[ALTO] SMBv1 activo en {len(v1)}: {', '.join(v1)}")
        ctx.out.line("        Protocolo obsoleto (WannaCry/EternalBlue). Desactívalo en esos equipos.")
    if nosign:
        ctx.out.check(False, f"[MEDIO] Firma SMB no obligatoria en {len(nosign)}: {', '.join(nosign)}")
        ctx.out.line("        Permite ataques de relay NTLM. Exige la firma por directiva de grupo (GPO).")
    if not v1 and not nosign:
        ctx.out.ok("Ningún equipo con SMBv1 ni con la firma SMB opcional.")
    vulns = [(h.ip, sid, title) for h in scan.up() for sid, title in h.vulnerable()]
    for ip, sid, title in vulns:
        ctx.out.check(False, f"[CRÍTICO] {ip} VULNERABLE: {sid} {title[:70]}")
    results.write(d / "resumen.txt", "\n".join(f"{r['ip']}\t{r['nombre']}\t{r['so']}\tSMBv1={r['smbv1']}\tfirma={r['firma']}"
                                                for r in rows) + "\n")
    audit.record("smb_resultado", " ".join(t), "OK", f"smbv1={len(v1)} sin_firma={len(nosign)}")
    recomendacion.render(ctx, recomendacion.from_smb(rows) + [recomendacion.Finding(ip, "CRÍTICO", title or sid, "vuln_confirmada",
                                                                                    evidencia=sid) for ip, sid, title in vulns])
    return True


def compartidos(ctx: Context, v: dict) -> bool:
    host = v["equipo"].strip()
    if not scope.gate(ctx, host, v, "smb_compartidos"):
        return False
    if not _targets(ctx, host) or " " in host:
        return False
    user = (v.get("usuario") or "").strip()
    if user and not system.has_cmd("smbclient"):
        ctx.out.error("Para usar una cuenta hace falta smbclient: instálalo (apt install smbclient) "
                      "o deja la cuenta vacía para comprobar el acceso anónimo.")
        return False
    if user:
        fd, auth = tempfile.mkstemp(prefix="opsdeck-smb-")
        try:
            dom, _, u = user.rpartition("\\")
            content = f"username = {u}\npassword = {v.get('password', '')}\n" + (f"domain = {dom}\n" if dom else "")
            os.write(fd, content.encode())
            os.close(fd)
            os.chmod(auth, 0o600)
            r = system.run(["smbclient", "-L", f"//{host}", "-A", auth, "-m", "SMB3", "-g"], timeout=60)
        finally:
            os.unlink(auth)
        audit.record("smb_compartidos", host, "OK" if r.ok else f"ERROR_{r.rc}", f"cuenta={user}")
        if not r.ok:
            msg = r.text.splitlines()[-1] if r.text else "error"
            ctx.out.error(f"No se pudo listar: {msg}")
            if "LOGON_FAILURE" in r.text:
                ctx.out.info("Usuario o contraseña incorrectos (usa DOMINIO\\usuario si es una cuenta del dominio).")
            return False
        shares = [l.split("|") for l in r.out.splitlines() if l.startswith("Disk|")]
        ctx.out.title(f"Recursos compartidos de {host} visibles para {user}")
        ctx.out.table(["Recurso", "Comentario"], [[s[1], s[2] if len(s) > 2 else ""] for s in shares])
        return True
    ctx.out.info("Comprobando qué se ve SIN credenciales (sesión anónima / invitado)...")
    d = results.new_dir("smb", f"compartidos_{host}")
    out = d / "compartidos"
    rc, _ = stream(ctx, ["nmap", "-Pn", "-p", "445", "--script", "smb-enum-shares", "-oA", str(out), host],
                   accion="smb_compartidos_anonimo", objetivo=host, show=False)
    scan = nmapxml.parse(out.with_suffix(".xml"))
    h = scan.up()[0] if scan.up() else None
    text = h.scripts.get("smb-enum-shares", "") if h else ""
    if not text:
        ctx.out.ok("No se pueden enumerar recursos sin credenciales (correcto).")
        return True
    rows = []
    for block in re.split(r"\n\s{2}(?=\\\\)", text):
        name = re.search(r"\\\\[^\\]+\\(\S+):", block)
        anon = re.search(r"Anonymous access: (\S+)", block)
        if name:
            rows.append([name.group(1), anon.group(1) if anon else "?"])
    ctx.out.table(["Recurso", "Acceso anónimo"], rows)
    risky = [r[0] for r in rows if r[1] not in ("<none>", "?") and not r[0].endswith("$")]
    if risky:
        ctx.out.check(False, f"[ALTO] Recursos accesibles sin contraseña: {', '.join(risky)}")
    recomendacion.render(ctx, recomendacion.from_smb_shares(host, risky))
    return True


NXC_PROTOCOLS = [("smb", "SMB"), ("ldap", "LDAP"), ("winrm", "WinRM"), ("rdp", "RDP (NLA)"), ("mssql", "SQL Server"),
                 ("ssh", "SSH"), ("ftp", "FTP"), ("wmi", "WMI"), ("vnc", "VNC"), ("nfs", "NFS")]
NXC_ENUM = [("", "Solo identificar (nombre, dominio, versión, firma, SMBv1)"), ("--shares", "Recursos compartidos"),
            ("--pass-pol", "Política de contraseñas"), ("--users", "Usuarios"), ("--groups", "Grupos"),
            ("--sessions", "Sesiones abiertas"), ("--loggedon-users", "Usuarios con sesión iniciada"),
            ("--disks", "Discos"), ("--rid-brute", "Usuarios por RID (sin credenciales, si se permite)")]
NXC_MODULES = [("", "Ninguno"), ("spooler", "Servicio de impresión activo (PrintNightmare/coerción)"),
               ("webdav", "WebClient activo (coerción a HTTP)"), ("ms17-010", "Comprobar MS17-010"),
               ("zerologon", "Comprobar Zerologon (solo comprobación)"), ("nopac", "Comprobar noPac"),
               ("petitpotam", "Comprobar PetitPotam (solo comprobación)"), ("enum_av", "Antivirus instalados"),
               ("gpp_password", "Contraseñas en GPP (SYSVOL)"), ("ldap-checker", "Firma y channel binding LDAP"),
               ("maq", "Cuota de equipos (MachineAccountQuota)"), ("adcs", "Servicios de certificados (AD CS)")]


def netexec(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "netexec"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    if t[:1] == ["-iL"]:                    # netexec acepta directamente la ruta del fichero como objetivo
        t = t[1:]
    tool = "netexec" if system.has_cmd("netexec") else "nxc"
    proto = v.get("protocolo") or "smb"
    if proto not in [p for p, _ in NXC_PROTOCOLS]:
        ctx.out.error("Protocolo no válido")
        return False
    args = [tool, proto, *t, "--threads", str(tooling.int_in(v.get("hilos"), 32, 1, 256)),
            "--timeout", str(tooling.int_in(v.get("espera"), 5, 1, 120))]
    user = (v.get("usuario") or "").strip()
    secret = None                        # (opción, valor) que se pasa en un fichero 0600, nunca en argv
    if user:
        dom, _, u = user.rpartition("\\")
        args += ["-u", u]
        if dom:
            args += ["-d", dom]
        if v.get("password"):
            secret = ("-p", v["password"])
        elif v.get("hash"):
            if not re.match(r"^([0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$", v["hash"]):
                ctx.out.error("Hash NT no válido (32 hex, o LM:NT)")
                return False
            secret = ("-H", v["hash"])   # el hash vale tanto como la contraseña (pass-the-hash)
        if v.get("local"):
            args.append("--local-auth")
        if v.get("kerberos"):
            args.append("-k")
    elif v.get("anonimo"):
        args += ["-u", "", "-p", ""]
    if v.get("enumerar"):
        args.append(v["enumerar"])
    if v.get("modulo"):
        args += ["-M", v["modulo"]]
    if proto == "smb" and v.get("relay"):
        d0 = results.new_dir("smb", "lista_relay")
        args += ["--gen-relay-list", str(d0 / "sin_firma.txt")]
    extra, err = tooling.extra_args(v.get("extra", ""), tooling.COMMON_FORBIDDEN + (
        "-x", "-X", "--exec-method", "--put-file", "--get-file", "--sam", "--lsa", "--ntds", "--dpapi", "--laps",
        "-M", "--continue-on-success", "--no-bruteforce", "--spider", "--spider_plus"))
    if err:
        ctx.out.error(err)
        return False
    d = results.new_dir("smb", f"netexec_{proto}_{v['objetivo'].replace('/', '_')}")
    pwfile = None
    if secret:
        import tempfile
        fd, pwfile = tempfile.mkstemp(prefix="opsdeck-nxc-")
        with os.fdopen(fd, "w") as fh:
            fh.write(secret[1] + "\n")
        args += [secret[0], pwfile]
    tooling.show_cmd(ctx, args + extra)
    try:
        rc, _ = stream(ctx, args + extra, accion=f"netexec_{proto}", objetivo=" ".join(t),
                       detalle=f"cuenta={user or ('anonima' if v.get('anonimo') else '-')} {v.get('enumerar', '')} "
                               f"{v.get('modulo', '')}", save_to=d / "netexec.txt")
    finally:
        if pwfile:
            os.unlink(pwfile)
    ctx.out.info("En cada línea: nombre, dominio, versión, firma (signing) y SMBv1. [+] = credenciales válidas.")
    if v.get("relay") and proto == "smb":
        ctx.out.info(f"Equipos sin firma SMB (candidatos a relay) en {d0 / 'sin_firma.txt'}")
    return rc == 0


def enum4linux(ctx: Context, v: dict) -> bool:
    host = v["equipo"].strip()
    if not scope.gate(ctx, host, v, "enum4linux") or not _targets(ctx, host) or " " in host:
        return False
    d = results.new_dir("smb", f"enum4linux_{host}")
    args = ["enum4linux-ng", "-A" if not v.get("rapido") else "-As", "-oJ", str(d / "enum4linux")]
    user = (v.get("usuario") or "").strip()
    env = None
    if user:
        args += ["-u", user]
        if v.get("password"):
            ctx.out.warn("enum4linux-ng recibe la contraseña como argumento (visible en la lista de procesos "
                         "mientras dura). Para evitarlo usa «Recursos compartidos» o netexec.")
            args += ["-p", v["password"]]
    args.append(host)
    tooling.show_cmd(ctx, args, hide={args.index("-p") + 1} if "-p" in args else None)
    rc, _ = stream(ctx, args, accion="enum4linux", objetivo=host, save_to=d / "enum4linux.txt", keep=200, env=env)
    ctx.out.info(f"Resultado (también en JSON) en {d}")
    return rc == 0


class Smb(Module):
    full = True
    id = "smb"
    name = "SMB y Windows"
    category = "Ciberseguridad"
    summary = "SMBv1, firma SMB (relay NTLM), sistema operativo y recursos compartidos"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
    optional = [cmd("smbclient", debian="smbclient", rhel="samba-client", suse="samba-client", arch="smbclient",
                    label="smbclient"), any_cmd(["netexec", "nxc"], label="netexec"),
                cmd("enum4linux-ng", label="enum4linux-ng")]
    help = """\
# SMB y Windows

> Solo contra sistemas propios o con autorización por escrito.

- **Seguridad SMB de una red**: para cada equipo con SMB (puerto 445) muestra el sistema operativo,
  si tiene **SMBv1** activo (protocolo obsoleto, el de WannaCry) y si la **firma SMB** es obligatoria.
  Sin firma obligatoria, un atacante en la red puede reutilizar autenticaciones (relay NTLM): en
  los controladores de dominio debe ser obligatoria siempre, y conviene en todos.
- **Recursos compartidos de un equipo**: sin credenciales comprueba qué se ve de forma **anónima**
  (no debería verse nada). Con una cuenta (`DOMINIO\\usuario`) lista lo que esa cuenta ve; necesita
  `smbclient`. La contraseña no se guarda ni aparece en la lista de procesos.
- **Barrido con netexec**: si netexec está instalado (Kali), un resumen muy rápido de toda la red, por
  SMB, LDAP, WinRM, RDP, SQL Server, SSH... Con opciones avanzadas: cuenta (contraseña o hash NT,
  local o Kerberos) o sesión anónima, **enumeración de solo lectura** (recursos, política de
  contraseñas, usuarios, grupos, sesiones, discos, RID), **módulos de comprobación** (spooler,
  WebClient, MS17-010, Zerologon, noPac, PetitPotam, GPP, firma LDAP, MachineAccountQuota, AD CS) y la
  **lista de equipos sin firma SMB**. No se permiten ejecución remota, volcados de credenciales ni
  fuerza bruta.
- **Enumeración completa (enum4linux-ng)**: si está instalado, todo lo que un equipo Windows/Samba
  cuenta por SMB y RPC (dominio, usuarios, grupos, recursos, política) con o sin cuenta.

**Opciones avanzadas de «Seguridad SMB»**: comprobar también MS17-010, MS08-067, SambaCry y
DoublePulsar (scripts de solo comprobación), puertos, velocidad, scripts y opciones de nmap.
"""

    def actions(self):
        obj = Param("objetivo", "Objetivo (red, IPs o fichero)", suggest=_subnets)
        A = dict(required=False, advanced=True)
        return [
            Action("seguridad", "Seguridad SMB de una red", seguridad, params=[
                obj, scope.ok_param(),
                Param("vulns", "Comprobar también MS17-010, MS08-067, SambaCry y DoublePulsar", "bool", False, **A),
                Param("puertos", "Puertos", "text", "139,445", **A),
                Param("scripts", "Scripts NSE adicionales", **A, help="Ej.: smb-enum-shares,smb-enum-users"),
                Param("tiempo", "Velocidad", "choice", "T4", choices=[("T2", "T2 educado"), ("T3", "T3 normal"),
                                                                      ("T4", "T4 rápido")], **A),
                tooling.p_extra("nmap")]),
            Action("compartidos", "Recursos compartidos de un equipo", compartidos, params=[
                Param("equipo", "Equipo (IP o nombre)"),
                Param("usuario", "Cuenta (DOMINIO\\usuario)", required=False),
                Param("password", "Contraseña (si indicas cuenta)", "password", required=False),
                scope.ok_param()]),
            Action("netexec", "Barrido con netexec", netexec, requires=[any_cmd(["netexec", "nxc"])], params=[
                obj, Param("protocolo", "Protocolo", "choice", "smb", choices=NXC_PROTOCOLS), scope.ok_param(),
                Param("usuario", "Cuenta (DOMINIO\\usuario)", **A), Param("password", "Contraseña", "password", **A),
                Param("hash", "Hash NT (en lugar de contraseña)", "password", **A),
                Param("local", "Cuenta local del equipo (--local-auth)", "bool", False, **A),
                Param("kerberos", "Autenticar con Kerberos (-k)", "bool", False, **A),
                Param("anonimo", "Sesión anónima (sin cuenta)", "bool", False, **A),
                Param("enumerar", "Enumerar (solo lectura)", "choice", "", choices=NXC_ENUM, **A),
                Param("modulo", "Módulo de comprobación", "choice", "", choices=NXC_MODULES, **A),
                Param("relay", "Guardar la lista de equipos sin firma SMB", "bool", False, **A),
                tooling.p_threads(32), tooling.p_timeout(5), tooling.p_extra("netexec", "--port 4455")],
                confirm=lambda v: "Se usará la cuenta indicada contra todos los objetivos: ¿tienes autorización? "
                                  "(un fallo repetido puede bloquear la cuenta)" if v.get("usuario") else ""),
            Action("enum4linux", "Enumeración completa (enum4linux-ng)", enum4linux, requires=[cmd("enum4linux-ng")],
                   params=[Param("equipo", "Equipo (IP o nombre)"), scope.ok_param(),
                           Param("usuario", "Cuenta", **A), Param("password", "Contraseña", "password", **A),
                           Param("rapido", "Sin consultas lentas (-As)", "bool", False, **A)]),
        ]
