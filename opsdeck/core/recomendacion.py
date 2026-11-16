"""Motor de recomendación: convierte los hallazgos de un análisis en el siguiente paso a dar.

Reacciona a lo que los escáneres reportan (no lleva CVE escritos a mano), así que una
vulnerabilidad recién salida se trata igual que una antigua. RECOMIENDA y SEÑALA la prueba o
la corrección que toca —confirmar, mitigar, parchear—; nunca explota ni lanza nada por su cuenta.
Para priorizar, consulta si existe un exploit público (searchsploit, solo lectura de exploit-db)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from . import system

# severidad normalizada y su orden (0 = más grave)
ORDEN = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
_NUCLEI = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO"}

# servicios en claro o de riesgo frecuente (puerto -> nombre legible)
INSEGUROS = {
    "telnet": "Telnet (credenciales en claro)", "ftp": "FTP (credenciales en claro)",
    "tftp": "TFTP (sin autenticación)", "rsh": "rsh (sin cifrar)", "rlogin": "rlogin (sin cifrar)",
    "rexec": "rexec (sin cifrar)", "vnc": "VNC (a menudo sin cifrar)", "pop3": "POP3 sin TLS",
    "imap": "IMAP sin TLS", "smtp": "SMTP sin TLS",
}


@dataclass
class Finding:
    objetivo: str
    severidad: str
    titulo: str
    tipo: str
    evidencia: str = ""
    datos: dict = field(default_factory=dict)


@dataclass
class Reco:
    objetivo: str
    severidad: str
    que: str
    accion: str
    herramienta: str = ""
    buscar_exploit: str = ""     # términos para searchsploit (producto + versión), si procede


# ---------------------------------------------------------------- adaptadores (datos -> hallazgos)

def _cvss_puerto(p) -> float:
    best = 0.0
    for m in re.finditer(r"\s(\d{1,2}\.\d)\s+https?://vulners", p.scripts.get("vulners", "")):
        best = max(best, float(m.group(1)))
    return best


def _sev_cvss(c: float) -> str:
    return "CRÍTICO" if c >= 9 else "ALTO" if c >= 7 else "MEDIO" if c >= 4 else "BAJO"


def from_scan(scan) -> list[Finding]:
    out: list[Finding] = []
    for h in scan.up():
        for sid, title in h.vulnerable():
            out.append(Finding(h.ip, "ALTO", title or sid, "vuln_confirmada", evidencia=sid, datos={"id": sid}))
        for p in h.open_ports():
            svc = (p.service or "").lower()
            if svc in INSEGUROS and not p.is_tls:
                out.append(Finding(h.ip, "MEDIO", INSEGUROS[svc], "servicio_inseguro",
                                   datos={"puerto": p.port, "servicio": svc}))
            c = _cvss_puerto(p)
            if c >= 7:
                prod = " ".join(x for x in (p.product, p.version) if x).strip()
                out.append(Finding(h.ip, _sev_cvss(c), f"{prod or p.service or 'servicio'} (CVSS {c} por versión)",
                                   "cve_version", evidencia=f"puerto {p.port}",
                                   datos={"producto": p.product, "version": p.version, "cvss": c, "puerto": p.port}))
    return out


def from_smb(rows: list[dict]) -> list[Finding]:
    out = []
    for r in rows:
        if r.get("smbv1"):
            out.append(Finding(r["ip"], "ALTO", "SMBv1 activo (WannaCry/EternalBlue)", "smbv1"))
        if r.get("firma") == "NO requerida":
            out.append(Finding(r["ip"], "MEDIO", "Firma SMB no obligatoria", "smb_sin_firma"))
    return out


def from_smb_shares(host: str, recursos: list[str]) -> list[Finding]:
    return [Finding(host, "ALTO", f"Recursos accesibles sin credenciales: {', '.join(recursos)}", "anon_share")] \
        if recursos else []


def from_web(result: dict) -> list[Finding]:
    url = result.get("url", "")
    out = []
    for lvl, txt in result.get("hallazgos", []):
        t = txt.lower()
        if "versiones obsoletas" in t or "tls 1.0" in t or "tls 1.1" in t:
            tipo = "tls_obsoleto"
        elif "caducado" in t:
            tipo = "cert_caducado"
        elif "caduca en" in t:
            tipo = "cert_pronto"
        elif "cabeceras de seguridad" in t:
            tipo = "cabeceras"
        elif "revela la versión" in t or "revela la tecnología" in t:
            tipo = "fuga_version"
        else:
            tipo = "web_otro"
        out.append(Finding(url, _norm(lvl), txt, tipo))
    return out


def from_nuclei(findings: list[dict]) -> list[Finding]:
    out = []
    for f in findings:
        info = f.get("info", {})
        sev = _NUCLEI.get(info.get("severity", ""), "INFO")
        if sev in ("INFO", "BAJO"):
            continue
        out.append(Finding(f.get("matched-at", f.get("host", "?")), sev,
                           info.get("name", f.get("template-id", "?")), "nuclei",
                           evidencia=f.get("template-id", ""), datos={"template": f.get("template-id", "")}))
    return out


def _norm(lvl: str) -> str:
    lvl = (lvl or "").upper()
    return lvl if lvl in ORDEN else {"ALTO": "ALTO", "MEDIO": "MEDIO", "BAJO": "BAJO"}.get(lvl, "BAJO")


# ---------------------------------------------------------------- reglas (hallazgo -> recomendación)

def _reco(f: Finding) -> Optional[Reco]:
    o, s = f.objetivo, f.severidad
    t = f.tipo
    if t == "smbv1":
        return Reco(o, "ALTO", "SMBv1 activo (protocolo de WannaCry/EternalBlue)",
                    "Desactiva SMBv1 en el equipo y vuelve a comprobar.", "SMB › Seguridad SMB")
    if t == "smb_sin_firma":
        return Reco(o, "MEDIO", "Firma SMB no obligatoria (riesgo de relay NTLM)",
                    "Exige la firma SMB por directiva de grupo (obligatoria en los controladores de dominio) y "
                    "re-verifica. En una prueba autorizada, el riesgo se valida con la técnica de relay NTLM.",
                    "SMB › Seguridad SMB")
    if t == "anon_share":
        return Reco(o, "ALTO", f.titulo,
                    "Restringe los permisos del recurso y revisa qué expone y quién debe acceder.", "SMB › Recursos compartidos")
    if t == "tls_obsoleto":
        return Reco(o, "MEDIO", "Acepta versiones de TLS obsoletas (1.0/1.1)",
                    "Deja solo TLS 1.2 o superior en el servidor y confírmalo.", "Web › TLS en profundidad (testssl)")
    if t == "cert_caducado":
        return Reco(o, "ALTO", f.titulo, "Renueva el certificado ya; el servicio da errores o avisos a los clientes.")
    if t == "cert_pronto":
        return Reco(o, "MEDIO", f.titulo, "Programa la renovación del certificado antes de que caduque.")
    if t == "cabeceras":
        return Reco(o, "BAJO", "Faltan cabeceras de seguridad",
                    "Añade HSTS, CSP y las anti-clickjacking en el servidor web.")
    if t == "fuga_version":
        return Reco(o, "BAJO", f.titulo, "Oculta la versión del servidor y de la tecnología en las cabeceras.")
    if t == "servicio_inseguro":
        return Reco(o, "MEDIO", f.titulo,
                    "Sustitúyelo por su alternativa cifrada (SSH, HTTPS, FTPS) o restríngelo por firewall.",
                    "Firewall")
    if t == "vuln_confirmada":
        return Reco(o, "ALTO", f"nmap marcó VULNERABLE: {f.titulo}",
                    "Confírmalo, prioriza y aplica el parche o una mitigación. Revisa el detalle del script NSE.",
                    "Vulnerabilidades (nuclei)")
    if t == "cve_version":
        prod = " ".join(x for x in (f.datos.get("producto", ""), f.datos.get("version", "")) if x).strip()
        return Reco(o, s, f.titulo,
                    "El CVSS por versión exagera en distros con parches: confírmalo. Comprueba si hay exploit "
                    "público para priorizar y aplica el parche de seguridad o mitiga.",
                    "Parches del sistema", buscar_exploit=prod)
    if t == "nuclei":
        return Reco(o, s, f"{f.titulo} (confirmado por nuclei)",
                    "Revisa las referencias de la plantilla en el .jsonl, prioriza por severidad y parchea o mitiga.",
                    buscar_exploit=f.titulo)
    if t == "web_otro":
        return Reco(o, s, f.titulo, "Revisa este hallazgo y decide si procede corregirlo.")
    return None


def recommend(findings: list[Finding]) -> list[Reco]:
    recos = [r for r in (_reco(f) for f in findings) if r]
    # quitar duplicados exactos conservando el orden
    vistos, uniq = set(), []
    for r in recos:
        k = (r.objetivo, r.que, r.accion)
        if k not in vistos:
            vistos.add(k)
            uniq.append(r)
    return sorted(uniq, key=lambda r: ORDEN.get(r.severidad, 9))


# ---------------------------------------------------------------- exploit público (consulta, no ejecución)

def public_exploit(terms: str) -> Optional[tuple[int, list[str]]]:
    terms = (terms or "").strip()
    if not terms or not system.has_cmd("searchsploit"):
        return None
    r = system.run(["searchsploit", "--json", terms], c_locale=True, timeout=30)
    if not r.ok:
        return None
    try:
        data = json.loads(r.out)
    except (json.JSONDecodeError, ValueError):
        return None
    res = data.get("RESULTS_EXPLOIT", []) or []
    titles = [e.get("Title", "") for e in res[:3]]
    return len(res), titles


# ---------------------------------------------------------------- presentación

def render(ctx, findings: list[Finding], scope_nets=None) -> int:
    """Muestra las recomendaciones derivadas de los hallazgos. Devuelve cuántas. No ejecuta pruebas."""
    recos = recommend(findings)
    if not recos:
        return 0
    ctx.out.title("Recomendaciones (siguiente paso)")
    ctx.out.info("La herramienta recomienda y señala; la decisión de ejecutar cualquier prueba es tuya.")
    buscados: dict[str, Optional[tuple]] = {}
    for r in recos:
        ctx.out.check(False, f"[{r.severidad}] {r.objetivo}: {r.que}")
        ctx.out.line(f"       → {r.accion}")
        if r.herramienta:
            ctx.out.line(f"         En opsdeck: {r.herramienta}")
        if r.buscar_exploit:
            if r.buscar_exploit not in buscados:
                buscados[r.buscar_exploit] = public_exploit(r.buscar_exploit)
            res = buscados[r.buscar_exploit]
            if res is None:
                pass
            elif res[0] == 0:
                ctx.out.line(f"         Exploit público: sin resultados en exploit-db para «{r.buscar_exploit}».")
            else:
                ctx.out.line(f"         Exploit público: {res[0]} en exploit-db "
                             f"(p. ej. {res[1][0][:70]}). Prioriza; «searchsploit {r.buscar_exploit}» para el detalle.")
    return len(recos)
