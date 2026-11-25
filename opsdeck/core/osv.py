"""Avisos de seguridad de Ubuntu y Debian en formato OSV (https://osv.dev), para saber en qué versión
de cada paquete corrigió la distribución un CVE.

Es la clave para descartar falsos positivos «por versión»: Ubuntu y Debian corrigen sin cambiar el
número original (OpenSSH 9.6p1 sigue siendo 9.6p1 con el parche), así que un escáner que solo lee el
número marca como vulnerable lo que ya está corregido.

Solo se descarga el aviso del CVE consultado (UBUNTU-CVE-… / DEBIAN-CVE-…) desde el almacenamiento
público de OSV, por HTTPS con verificación de certificado. Lo único que sale del equipo es el
identificador del CVE: nunca equipos, direcciones ni resultados. Se guarda en caché unos días y se
puede desactivar con [verificacion] consultar_osv = false (entonces solo se usa la caché)."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import debver, paths
from .config import settings

BASE = "https://osv-vulnerabilities.storage.googleapis.com"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_BYTES = 4 * 1024 * 1024
CACHE_DAYS = 3
DISTROS = {"ubuntu": ("Ubuntu", "UBUNTU"), "debian": ("Debian", "DEBIAN")}


def cache_dir() -> Path:
    return paths.DATA_DIR / "cache" / "osv"


@dataclass
class Afectado:
    paquete: str             # paquete fuente
    ecosistema: str          # Ubuntu:24.04:LTS, Debian:12...
    corregido: str = ""      # versión con la corrección ('' = sin corrección publicada)
    versiones: list[str] = field(default_factory=list)


@dataclass
class Aviso:
    id: str
    distro: str
    afectados: list[Afectado] = field(default_factory=list)
    resumen: str = ""
    error: str = ""          # por qué no hay datos ('' si los hay)
    existe: bool = True      # False si la distribución no tiene aviso para ese CVE


def normalize_cve(text: str) -> str:
    t = (text or "").strip().upper()
    return t if CVE_RE.match(t) else ""


def _parse(data: dict, distro: str) -> Aviso:
    av = Aviso(str(data.get("id", "")), distro, resumen=str(data.get("summary") or data.get("details") or "")[:400])
    for a in data.get("affected") or []:
        pkg = a.get("package") or {}
        name, eco = str(pkg.get("name", "")), str(pkg.get("ecosystem", ""))
        if not name or not eco:
            continue
        fixed = ""
        for r in a.get("ranges") or []:
            if r.get("type") != "ECOSYSTEM":
                continue
            for ev in r.get("events") or []:
                f = str(ev.get("fixed", "") or "")
                if f and debver.valid(f):
                    fixed = f
        vers = [str(v) for v in (a.get("versions") or []) if debver.valid(str(v))][:500]
        av.afectados.append(Afectado(name, eco, fixed, vers))
    return av


def _fetch(url: str, timeout: int) -> tuple[Optional[bytes], str]:
    req = urllib.request.Request(url, headers={"User-Agent": "opsdeck", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:       # noqa: S310 (https fijo)
            body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                return None, "respuesta demasiado grande"
            return body, ""
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):        # el almacenamiento de OSV responde 404/403 si no hay aviso
            return b"", ""
        return None, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, str(getattr(e, "reason", e))[:200]


def aviso(cve: str, distro: str, timeout: int = 20, online: Optional[bool] = None) -> Aviso:
    """Aviso de la distribución ('ubuntu' o 'debian') para un CVE, desde la caché o desde OSV."""
    cve = normalize_cve(cve)
    if not cve or distro not in DISTROS:
        return Aviso(cve, distro, error="CVE o distribución no válidos", existe=False)
    folder, prefix = DISTROS[distro]
    vid = f"{prefix}-{cve}"
    cdir = cache_dir()
    cfile = cdir / f"{vid}.json"
    if online is None:
        online = settings().getboolean("verificacion", "consultar_osv", fallback=True)
    fresh = cfile.exists() and time.time() - cfile.stat().st_mtime < CACHE_DAYS * 86400
    if not fresh and online:
        body, err = _fetch(f"{BASE}/{folder}/{vid}.json", timeout)
        if body is not None:
            try:
                paths.ensure_private_dir(paths.DATA_DIR, 0o750)
                paths.ensure_private_dir(paths.DATA_DIR / "cache", 0o700)
                paths.ensure_private_dir(cdir, 0o700)
                tmp = cfile.with_suffix(".tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(body)
                os.replace(tmp, cfile)
            except OSError:
                pass
            if not body:
                return Aviso(vid, distro, existe=False)
            try:
                return _parse(json.loads(body), distro)
            except (ValueError, AttributeError, TypeError):
                return Aviso(vid, distro, error="respuesta de OSV no válida")
        if not cfile.exists():
            return Aviso(vid, distro, error=f"no se pudo consultar OSV ({err})")
    if not cfile.exists():
        return Aviso(vid, distro, error="sin datos en caché y la consulta a OSV está desactivada")
    try:
        body = cfile.read_bytes()[:MAX_BYTES]
        if not body:
            return Aviso(vid, distro, existe=False)
        return _parse(json.loads(body), distro)
    except (OSError, ValueError, AttributeError, TypeError):
        return Aviso(vid, distro, error="caché de OSV dañada")


# ---------------------------------------------------------------- equipo local

def local_ecosystem() -> tuple[str, str]:
    """(distro, ecosistema OSV) de este equipo: ('ubuntu', 'Ubuntu:24.04:LTS'), ('debian', 'Debian:12')...
    Kali es «rolling» (no hay ecosistema propio): se compara con Debian por versión original."""
    from . import system
    r = system.os_release()
    ident = r.get("ID", "").lower()
    ver = r.get("VERSION_ID", "")
    if ident == "ubuntu" and ver:
        return "ubuntu", f"Ubuntu:{ver}" + (":LTS" if "LTS" in r.get("VERSION", "") else "")
    if ident == "debian" and ver:
        return "debian", f"Debian:{ver.split('.')[0]}"
    if ident == "kali" or "debian" in r.get("ID_LIKE", "").lower():
        return "debian", ""
    return "", ""


def installed_sources() -> dict[str, str]:
    """Paquete fuente -> versión fuente instalada (dpkg). Vacío si no es un sistema dpkg."""
    from . import system
    if not system.has_cmd("dpkg-query"):
        return {}
    r = system.run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n"],
                   c_locale=True, timeout=60)
    out: dict[str, str] = {}
    for line in r.out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0].startswith("ii"):
            continue
        src, ver = parts[1].strip(), parts[2].strip()
        if src and debver.valid(ver) and (src not in out or debver.compare(ver, out[src]) > 0):
            out[src] = ver
    return out
