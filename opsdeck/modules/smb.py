"""SMB y Windows: SMBv1, firma SMB (riesgo de relay NTLM), sistema operativo y recursos compartidos.

Funciona solo con nmap (scripts NSE). Si están instalados, usa smbclient para listar recursos con
credenciales y netexec para un barrido rápido. Solo contra sistemas propios o autorizados."""

from __future__ import annotations

import os
import re
import tempfile

from ..core import audit, nmapxml, results, scope, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from .escaneo import _subnets, _targets


def analyze_host(h: nmapxml.Host) -> dict:
    proto = h.scripts.get("smb-protocols", "")
    sec2 = h.scripts.get("smb2-security-mode", "")
    sec1 = h.scripts.get("smb-security-mode", "")
    osd = h.scripts.get("smb-os-discovery", "")
    smbv1 = "SMBv1" in proto or "NT LM 0.12" in proto
    if "required" in sec2 and "not required" not in sec2:
        signing = "requerida"
    elif sec2 or sec1:
        signing = "NO requerida" if ("not required" in sec2 or "disabled" in sec1 or "supported" in sec1) else "?"
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
    rc, _ = stream(ctx, ["nmap", "-Pn", "-p", "139,445", "--open", "--script",
                         "smb-protocols,smb2-security-mode,smb-security-mode,smb-os-discovery", "-oA", str(out), *t],
                   accion="smb_seguridad", objetivo=" ".join(t), keep=10)
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
    results.write(d / "resumen.txt", "\n".join(f"{r['ip']}\t{r['nombre']}\t{r['so']}\tSMBv1={r['smbv1']}\tfirma={r['firma']}"
                                                for r in rows) + "\n")
    audit.record("smb_resultado", " ".join(t), "OK", f"smbv1={len(v1)} sin_firma={len(nosign)}")
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
    return True


def netexec(ctx: Context, v: dict) -> bool:
    if not scope.gate(ctx, v["objetivo"], v, "netexec"):
        return False
    t = _targets(ctx, v["objetivo"])
    if not t:
        return False
    tool = "netexec" if system.has_cmd("netexec") else "nxc"
    d = results.new_dir("smb", f"netexec_{v['objetivo'].replace('/', '_')}")
    rc, _ = stream(ctx, [tool, "smb", *t], accion="netexec_smb", objetivo=" ".join(t), save_to=d / "netexec.txt")
    ctx.out.info("En cada línea: nombre, dominio, versión de Windows, firma (signing) y SMBv1.")
    return rc == 0


class Smb(Module):
    full = True
    id = "smb"
    name = "SMB y Windows"
    category = "Ciberseguridad"
    summary = "SMBv1, firma SMB (relay NTLM), sistema operativo y recursos compartidos"
    requires = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap")]
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
- **Barrido con netexec**: si netexec está instalado (Kali), un resumen muy rápido de toda la red.
"""

    def actions(self):
        obj = Param("objetivo", "Objetivo (red, IPs o fichero)", suggest=_subnets)
        return [
            Action("seguridad", "Seguridad SMB de una red", seguridad, params=[obj, scope.ok_param()]),
            Action("compartidos", "Recursos compartidos de un equipo", compartidos, params=[
                Param("equipo", "Equipo (IP o nombre)"),
                Param("usuario", "Cuenta (opcional, DOMINIO\\usuario)", required=False),
                Param("password", "Contraseña (si indicas cuenta)", "password", required=False),
                scope.ok_param()]),
            Action("netexec", "Barrido rápido con netexec", netexec, params=[obj, scope.ok_param()],
                   requires=[cmd("netexec", debian="netexec")] if system.has_cmd("netexec") else [cmd("nxc")]),
        ]
