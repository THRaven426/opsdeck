"""Verificación de vulnerabilidades: confirmar o descartar, de forma segura, lo que dice un análisis.

No explota nada: para cada CVE comprueba si la deficiencia se cumple de verdad en ese equipo, con
pruebas que no dan acceso, no cambian nada y no prueban contraseñas. Tres comprobaciones:

- Paquetes de la distribución (backports): compara la versión del paquete con la versión en la que
  Ubuntu/Debian publicó la corrección (avisos OSV). Elimina el falso positivo más habitual de Nessus,
  OpenVAS y vulners: «OpenSSH 9.6p1 es vulnerable» cuando el paquete ya lleva el parche.
- Plantillas de nuclei de ese CVE, solo las seguras (sin dos, fuzz, intrusive, fuerza bruta ni
  credenciales por defecto; sin plantillas que ejecutan código local o un navegador).
- Scripts NSE de nmap que lo comprueban y que nmap clasifica a la vez como «vuln» y «safe».

Cada verificación se guarda en su propia carpeta; los análisis de los que parte solo se leen."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from ..core import audit, debver, feeds, informes, nmapxml, osv, results, scope, system, tooling
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.config import settings
from ..core.ops import stream

CONFIRMADA, NO_APLICA, NO_REPRODUCIDA, NO_CONCLUYENTE = "CONFIRMADA", "NO APLICA", "NO REPRODUCIDA", "NO CONCLUYENTE"
ORDEN = {CONFIRMADA: 0, NO_APLICA: 1, NO_REPRODUCIDA: 2, NO_CONCLUYENTE: 3}
EXPLICACION = {
    CONFIRMADA: "la deficiencia se cumple: la ha visto una prueba segura o el paquete es anterior a la corrección",
    NO_APLICA: "no afecta: el paquete ya lleva la corrección o no está afectado",
    NO_REPRODUCIDA: "la prueba segura se ejecutó y el servicio no respondió como vulnerable",
    NO_CONCLUYENTE: "no hay forma segura de comprobarlo o no se pudo probar: revisar a mano",
}

# Etiquetas de nuclei que nunca se lanzan: pueden tumbar, alterar o forzar el servicio.
UNSAFE_TAGS = ("dos", "fuzz", "fuzzing", "intrusive", "brute-force", "bruteforce", "default-login", "dast")
# Tipos de plantilla que no se lanzan: ejecutan código en este equipo, abren un navegador o leen ficheros.
UNSAFE_TYPES = ("code", "headless", "javascript", "file", "workflows", "fuzzing")
NUCLEI_TYPES = ("http", "requests", "network", "tcp", "dns", "ssl", "websocket", "whois") + UNSAFE_TYPES
# Categorías NSE que se rechazan aunque el script sea «safe»
NSE_REJECT = {"intrusive", "dos", "exploit", "brute", "external", "fuzzer"}
NSE_DIRS = (Path("/usr/share/nmap/scripts"), Path("/usr/local/share/nmap/scripts"))
PUBLIC_OAST = ("oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh",
               "interactsh.com")

CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$")
SESION_RE = re.compile(r"^\d{8}_\d{6}_[A-Za-z0-9._-]{1,80}$")
SSH_BANNER = re.compile(r"OpenSSH[_ ](?P<up>\d[\w.]*)[ _-](?P<distro>Ubuntu|Debian)[ _-](?P<rev>[0-9][\w.+~]*)", re.I)
MANUAL_RE = re.compile(r"^(?P<pkg>[a-z0-9][a-z0-9.+-]{0,80})\s+(?P<ver>\S{1,128})\s+(?P<distro>ubuntu|debian)$", re.I)


# ---------------------------------------------------------------- resultados

@dataclass
class Prueba:
    motor: str
    estado: str
    detalle: str
    evidencia: list[str] = field(default_factory=list)


@dataclass
class Veredicto:
    cve: str
    objetivo: str
    estado: str = NO_CONCLUYENTE
    pruebas: list[Prueba] = field(default_factory=list)
    carpeta: str = ""

    def motivo(self) -> str:
        decisiva = next((p for p in self.pruebas if p.estado == self.estado), None)
        return f"{decisiva.motor}: {decisiva.detalle}" if decisiva else "sin pruebas"


def combinar(pruebas: list[Prueba]) -> str:
    """La prueba más fuerte decide: una confirmación gana a todo; «corregido según la distribución» a
    una prueba sin respuesta; y sin ninguna prueba útil, no concluyente."""
    if not pruebas:
        return NO_CONCLUYENTE
    return min((p.estado for p in pruebas), key=lambda s: ORDEN[s])


# ---------------------------------------------------------------- objetivos

@dataclass
class Objetivo:
    host: str
    port: Optional[int] = None
    url: str = ""

    @property
    def texto(self) -> str:
        if self.url:
            return self.url
        return f"{self.host}:{self.port}" if self.port else self.host

    @property
    def local(self) -> bool:
        return self.host == "local"


def parse_objetivo(text: str) -> tuple[Optional[Objetivo], str]:
    t = (text or "").strip()
    if not t:
        return None, "Falta el objetivo"
    if t.lower() in ("local", "este equipo", "localhost-paquetes"):
        return Objetivo("local"), ""
    if " " in t or "\t" in t:
        return None, "Indica un solo objetivo (equipo, equipo:puerto o URL)"
    if "://" in t:
        m = re.match(r"^(https?)://([^/\s?#]+)([^\s]*)$", t)
        if not m:
            return None, "URL no válida: solo http:// o https://"
        hostport = m.group(2).rsplit("@", 1)[-1]
        host = scope.host_of(f"{m.group(1)}://{hostport}")
        port = None
        pm = re.search(r":(\d{1,5})$", hostport)
        port = int(pm.group(1)) if pm else (443 if m.group(1) == "https" else 80)
        if not 1 <= port <= 65535:
            return None, "Puerto fuera de rango"
        if not _host_ok(host):
            return None, "Equipo no válido en la URL"
        return Objetivo(host, port, f"{m.group(1)}://{hostport}{m.group(3)}"), ""
    host = scope.host_of(t)
    port = None
    pm = re.match(r"^\[?[^\]]+\]?:(\d{1,5})$", t) if t.count(":") == 1 or t.startswith("[") else None
    if pm:
        port = int(pm.group(1))
    if port is not None and not 1 <= port <= 65535:
        return None, "Puerto fuera de rango"
    if not _host_ok(host):
        return None, f"Objetivo no válido: {t}"
    return Objetivo(host, port), ""


def _host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.match(host)) and not host.startswith("-") and "/" not in host


# ---------------------------------------------------------------- paquetes de la distribución

def paquete_de_banner(text: str) -> Optional[tuple[str, str, str]]:
    """(paquete fuente, versión, distro) a partir de un banner o de la versión que vio nmap.
    Solo cuando el banner incluye la revisión del paquete (OpenSSH en Ubuntu/Debian la incluye)."""
    m = SSH_BANNER.search(text or "")
    if not m:
        return None
    ver = f"{m.group('up')}-{m.group('rev')}"
    return ("openssh", ver, m.group("distro").lower()) if debver.valid(ver) else None


def ssh_banner(host: str, port: int, timeout: float = 5.0) -> str:
    """Primera línea que envía un servidor SSH al conectar (lo mismo que ve cualquier cliente)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
    except OSError:
        return ""
    line = data.split(b"\n", 1)[0].decode("ascii", "replace").strip()
    return re.sub(r"[^\x20-\x7e]", "", line)[:200]


def _misma_rama(a: osv.Afectado, version: str) -> bool:
    up = debver.upstream(version)
    return (bool(a.corregido) and debver.upstream(a.corregido) == up) or any(debver.upstream(x) == up for x in a.versiones)


def _con_epoca(version: str, ref: str) -> str:
    """El banner no lleva la época del paquete («1:» en openssh): se toma la de la versión de referencia."""
    if ":" not in version and ":" in ref:
        return ref.split(":", 1)[0] + ":" + version
    return version


def _decidir(a: osv.Afectado, version: str) -> tuple[str, str]:
    version = _con_epoca(version, a.corregido or (a.versiones[0] if a.versiones else ""))
    if not a.corregido:
        return CONFIRMADA, f"{a.paquete} {version} ({a.ecosistema}): afectado y sin corrección publicada"
    if debver.compare(version, a.corregido) >= 0:
        return NO_APLICA, f"{a.paquete} {version} ya incluye la corrección (publicada en {a.corregido}, {a.ecosistema})"
    return CONFIRMADA, f"{a.paquete} {version} es anterior a la corrección {a.corregido} ({a.ecosistema})"


def comprobar_paquete(cve: str, distro: str, paquete: str, version: str, d: Optional[Path] = None) -> Prueba:
    """Prueba de backport para un paquete con versión conocida (de un banner o indicada a mano)."""
    motor = "paquetes de la distribución"
    av = osv.aviso(cve, distro)
    if av.error:
        return Prueba(motor, NO_CONCLUYENTE, f"sin datos de {distro} para {cve}: {av.error}")
    if not av.existe:
        return Prueba(motor, NO_CONCLUYENTE, f"{distro.capitalize()} no tiene aviso para {cve}")
    if d:
        _guardar_aviso(d, av)
    propios = [a for a in av.afectados if a.paquete == paquete]
    if not propios:
        return Prueba(motor, NO_APLICA, f"el aviso de {distro.capitalize()} para {cve} no incluye el paquete {paquete}")
    rama = [a for a in propios if _misma_rama(a, version)]
    if not rama:
        return Prueba(motor, NO_CONCLUYENTE, f"{paquete} {version}: no coincide con ninguna versión de {distro} "
                      "del aviso (¿otra versión de la distribución o paquete propio?)")
    decis = {_decidir(a, version) for a in rama}
    estados = {e for e, _ in decis}
    if len(estados) > 1:
        return Prueba(motor, NO_CONCLUYENTE, "; ".join(t for _, t in sorted(decis)))
    estado = estados.pop()
    return Prueba(motor, estado, sorted(decis)[0][1])


def comprobar_local(cve: str, d: Optional[Path] = None, fuentes: Optional[dict] = None) -> Prueba:
    """¿Afecta el CVE a los paquetes instalados en ESTE equipo?"""
    motor = "paquetes de este equipo"
    distro, eco = osv.local_ecosystem()
    if not distro:
        return Prueba(motor, NO_CONCLUYENTE, "solo disponible en Debian, Ubuntu y derivadas (Kali)")
    av = osv.aviso(cve, distro)
    if av.error:
        return Prueba(motor, NO_CONCLUYENTE, f"sin datos de {distro} para {cve}: {av.error}")
    if not av.existe:
        return Prueba(motor, NO_APLICA, f"{distro.capitalize()} no tiene aviso para {cve}: no afecta a sus paquetes")
    if d:
        _guardar_aviso(d, av)
    inst = fuentes if fuentes is not None else osv.installed_sources()
    if not inst:
        return Prueba(motor, NO_CONCLUYENTE, "no se pudo leer la lista de paquetes instalados (dpkg)")
    filas = []
    for pkg in sorted({a.paquete for a in av.afectados}):
        if pkg not in inst:
            continue
        cand = [a for a in av.afectados if a.paquete == pkg]
        if eco:
            sel = [a for a in cand if a.ecosistema == eco]
            if not sel:
                filas.append((NO_APLICA, f"{pkg} {inst[pkg]}: {eco} no figura como afectada en el aviso"))
                continue
        else:       # Kali (rolling): la rama de Debian más reciente del aviso
            def _num(a):
                m = re.match(r"Debian:(\d+)$", a.ecosistema)
                return int(m.group(1)) if m else -1
            best = max(cand, key=_num)
            sel = [best] if _num(best) >= 0 else []
            if not sel:
                continue
        filas.append(_decidir(sel[0], inst[pkg]))
    if not filas:
        return Prueba(motor, NO_APLICA, "ninguno de los paquetes afectados está instalado")
    estado = combinar([Prueba(motor, e, t) for e, t in filas])
    return Prueba(motor, estado, "; ".join(t for e, t in filas if e == estado)[:600])


def _guardar_aviso(d: Path, av: osv.Aviso) -> None:
    try:
        results.write(d / f"aviso_{av.distro}.json", json.dumps(asdict(av), ensure_ascii=False, indent=1))
    except OSError:
        pass


# ---------------------------------------------------------------- nuclei

@dataclass
class Plantilla:
    path: Path
    tags: set[str]
    tipos: set[str]
    oast: bool
    motivo: str = ""            # por qué no se lanza ('' = segura)

    @property
    def nombre(self) -> str:
        return self.path.name


def nuclei_dir() -> Optional[Path]:
    return next((p for p in feeds.NUCLEI_DIRS if p.is_dir()), None)


def _leer_plantilla(p: Path) -> Optional[Plantilla]:
    try:
        if p.is_symlink() or p.stat().st_size > 512 * 1024:
            return None
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"(?m)^\s+tags:\s*(.+)$", text)
    tags = {t.strip().strip("'\"").lower() for t in (m.group(1).split(",") if m else []) if t.strip()}
    tipos = {k for k in re.findall(r"(?m)^([a-z]+)\s*:", text) if k in NUCLEI_TYPES}
    oast = "interactsh" in text
    return Plantilla(p, tags, tipos, oast)


def plantillas_cve(cve: str, permitir_rce: bool = False, oast_ok: bool = False) -> list[Plantilla]:
    base = nuclei_dir()
    if base is None:
        return []
    out = []
    for p in sorted(base.rglob(f"{cve}.yaml")):
        t = _leer_plantilla(p)
        if t is None:
            continue
        parts = {x.lower() for x in p.relative_to(base).parts}
        malas = sorted(t.tags & set(UNSAFE_TAGS))
        tipos = sorted(t.tipos & set(UNSAFE_TYPES))
        if "dast" in parts or "fuzzing" in parts:
            t.motivo = "plantilla de fuzzing (DAST)"
        elif malas:
            t.motivo = "etiquetas no seguras: " + ", ".join(malas)
        elif tipos:
            t.motivo = "tipo no permitido: " + ", ".join(tipos)
        elif "rce" in t.tags and not permitir_rce:
            t.motivo = "confirma ejecutando una orden inocua en el objetivo (rce): márcalo si lo autorizas"
        elif t.oast and not oast_ok:
            t.motivo = "necesita un servidor interactsh propio ([verificacion] interactsh_servidor)"
        out.append(t)
    return out


def interactsh() -> tuple[str, str]:
    """(servidor, problema). Solo se acepta un interactsh propio y dentro de la red interna."""
    url = settings().get("verificacion", "interactsh_servidor", fallback="").strip()
    if not url:
        return "", ""
    m = re.match(r"^(https?)://([A-Za-z0-9.-]{1,253})(:\d{1,5})?/?$", url)
    if not m:
        return "", f"interactsh_servidor no válido: {url[:80]} (formato https://servidor[:puerto])"
    host = m.group(2).lower().rstrip(".")
    if any(host == d or host.endswith("." + d) for d in PUBLIC_OAST):
        return "", "interactsh_servidor apunta a un servidor público: solo se permite uno propio e interno"
    try:
        ips = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):
        ips = set()
    if not ips:
        return "", f"interactsh_servidor no se resuelve: {host}"
    nets = scope.authorized_networks()
    fuera = [str(ip) for ip in ips if not (ip.is_private or any(ip.version == n.version and ip in n for n in nets))]
    if fuera:
        return "", f"interactsh_servidor no es interno ({', '.join(fuera)}): solo se permite uno propio en la red interna"
    return url.rstrip("/"), ""


def args_nuclei(target: str, tpls: list[Plantilla], out: Path, server: str) -> list[str]:
    args = ["nuclei", "-u", target]
    for t in tpls:
        args += ["-t", str(t.path)]
    args += ["-jsonl", "-o", str(out), "-nc", "-silent", "-duc",
             "-etags", ",".join(UNSAFE_TAGS), "-ept", ",".join(x for x in UNSAFE_TYPES if x != "workflows" and x != "fuzzing"),
             "-rate-limit", "10", "-c", "2", "-timeout", "10", "-retries", "1"]
    args += ["-iserver", server] if server else ["-no-interactsh"]
    return args


def run_nuclei(ctx: Context, cve: str, obj: Objetivo, d: Path, permitir_rce: bool) -> Prueba:
    motor = "nuclei"
    if not system.has_cmd("nuclei"):
        return Prueba(motor, NO_CONCLUYENTE, "nuclei no está instalado")
    if nuclei_dir() is None:
        return Prueba(motor, NO_CONCLUYENTE, "plantillas de nuclei sin descargar (Fuentes de datos › Actualizar)")
    server, problem = interactsh()
    if problem:
        ctx.out.warn(problem + ". Las plantillas que lo necesitan no se lanzan.")
    tpls = plantillas_cve(cve, permitir_rce, bool(server))
    if not tpls:
        return Prueba(motor, NO_CONCLUYENTE, f"no hay plantilla de nuclei para {cve}")
    ok = [t for t in tpls if not t.motivo]
    for t in tpls:
        if t.motivo:
            ctx.out.info(f"No se lanza {t.nombre}: {t.motivo}")
    if not ok:
        return Prueba(motor, NO_CONCLUYENTE, "; ".join(sorted({t.motivo for t in tpls})))
    out = d / "nuclei.jsonl"
    target = obj.url or obj.texto
    args = args_nuclei(target, ok, out, server)
    results.write(d / "orden_nuclei.txt", " ".join(args) + "\n")
    tooling.show_cmd(ctx, args)
    rc, _ = stream(ctx, args, accion="verificacion_nuclei", objetivo=target, detalle=cve, keep=30)
    if rc in (system.STOPPED, -15):
        return Prueba(motor, NO_CONCLUYENTE, "detenido por el usuario")
    hits = []
    if out.exists():
        for line in out.read_text(errors="replace").splitlines():
            try:
                f = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(f, dict):
                hits.append(f)
    if hits:
        f = hits[0]
        extra = f.get("extracted-results") or []
        donde = str(f.get("matched-at") or f.get("host") or target)[:120]
        return Prueba(motor, CONFIRMADA, f"{f.get('template-id', cve)} coincide en {donde}"
                      + (f" [{', '.join(map(str, extra))[:80]}]" if extra else ""), [str(out)])
    if rc != 0:
        return Prueba(motor, NO_CONCLUYENTE, f"nuclei terminó con error (código {rc})")
    return Prueba(motor, NO_REPRODUCIDA, f"{len(ok)} plantilla(s) segura(s) sin coincidencia: "
                  + ", ".join(t.nombre for t in ok)[:200])


# ---------------------------------------------------------------- nmap (NSE)

def _nse_dir() -> Optional[Path]:
    return next((p for p in NSE_DIRS if (p / "script.db").is_file()), None)


def _categorias(base: Path) -> dict[str, set[str]]:
    cats: dict[str, set[str]] = {}
    try:
        text = (base / "script.db").read_text(errors="replace")
    except OSError:
        return cats
    for m in re.finditer(r'filename = "([\w.-]+)\.nse", categories = \{([^}]*)\}', text):
        cats[m.group(1)] = set(re.findall(r'"(\w+)"', m.group(2)))
    return cats


def scripts_cve(cve: str) -> list[tuple[str, str]]:
    """[(script, motivo)] de los scripts NSE que comprueban ese CVE. motivo '' = se puede lanzar."""
    base = _nse_dir()
    if base is None:
        return []
    cats = _categorias(base)
    year_num = cve[4:].lower()
    out = []
    for name, c in sorted(cats.items()):
        p = base / f"{name}.nse"
        if f"cve{year_num}" not in name.lower():
            try:
                if p.is_symlink() or p.stat().st_size > 1024 * 1024 or cve.upper() not in p.read_text(errors="replace").upper():
                    continue
            except OSError:
                continue
        if "slowloris" in name:
            motivo = "comprobación de denegación de servicio"
        elif c & NSE_REJECT:
            motivo = "categorías no seguras: " + ", ".join(sorted(c & NSE_REJECT))
        elif not {"vuln", "safe"} <= c:
            motivo = "nmap no lo clasifica como «vuln» y «safe» a la vez"
        else:
            motivo = ""
        out.append((name, motivo))
    return out


def args_nmap(obj: Objetivo, scripts: list[str], xml: Path) -> list[str]:
    ports = ["-p", str(obj.port)] if obj.port else ["--top-ports", "100"]
    return ["nmap", "-Pn", "-sV", "--version-light", *ports, "--script", ",".join(scripts),
            "--script-timeout", "90s", "--host-timeout", "5m", "--max-retries", "2", "-T3",
            "-oX", str(xml), obj.host]


def run_nmap(ctx: Context, cve: str, obj: Objetivo, d: Path) -> Prueba:
    motor = "nmap (NSE)"
    if not system.has_cmd("nmap"):
        return Prueba(motor, NO_CONCLUYENTE, "nmap no está instalado")
    cands = scripts_cve(cve)
    if not cands:
        return Prueba(motor, NO_CONCLUYENTE, f"no hay script NSE para {cve}")
    for name, motivo in cands:
        if motivo:
            ctx.out.info(f"No se lanza {name}: {motivo}")
    ok = [n for n, m in cands if not m]
    if not ok:
        return Prueba(motor, NO_CONCLUYENTE, "; ".join(sorted({m for _, m in cands})))
    xml = d / "nmap.xml"
    args = args_nmap(obj, ok, xml)
    results.write(d / "orden_nmap.txt", " ".join(args) + "\n")
    tooling.show_cmd(ctx, args)
    rc, _ = stream(ctx, args, accion="verificacion_nmap", objetivo=obj.texto, detalle=cve, keep=30)
    if rc in (system.STOPPED, -15):
        return Prueba(motor, NO_CONCLUYENTE, "detenido por el usuario")
    scan = nmapxml.parse(xml)
    h = scan.hosts[0] if scan.hosts else None
    if rc != 0 or h is None:
        return Prueba(motor, NO_CONCLUYENTE, f"nmap no pudo analizar el objetivo (código {rc})")
    if obj.port:
        p = next((x for x in h.ports if x.port == obj.port), None)
        if p is None or p.state != "open":
            return Prueba(motor, NO_CONCLUYENTE, f"el puerto {obj.port} no está abierto ({p.state if p else 'sin respuesta'})")
    salidas = {sid: txt for x in h.ports for sid, txt in x.scripts.items() if sid in ok}
    salidas.update({sid: txt for sid, txt in h.scripts.items() if sid in ok})
    for sid, txt in salidas.items():
        if re.search(r"State: (LIKELY )?VULNERABLE", txt):
            prob = "probable" if "LIKELY" in txt else "confirmada"
            return Prueba(motor, CONFIRMADA, f"{sid}: vulnerabilidad {prob}", [str(xml)])
    if salidas:
        return Prueba(motor, NO_REPRODUCIDA, ", ".join(salidas) + ": no vulnerable", [str(xml)])
    return Prueba(motor, NO_REPRODUCIDA, ", ".join(ok) + ": sin respuesta (servicio distinto o no expuesto)", [str(xml)])


# ---------------------------------------------------------------- una verificación

MOTORES = [("auto", "Automático: todo lo que se pueda comprobar"), ("paquetes", "Solo paquetes de la distribución (backports)"),
           ("nuclei", "Solo nuclei"), ("nmap", "Solo nmap (NSE)")]


def verificar(ctx: Context, cve: str, obj: Objetivo, d: Path, *, motor: str = "auto", paquete: str = "",
              banner: str = "", permitir_rce: bool = False, fuentes: Optional[dict] = None) -> Veredicto:
    ver = Veredicto(cve, "este equipo" if obj.local else obj.texto, carpeta=str(d))
    pr = ver.pruebas
    if obj.local:
        pr.append(comprobar_local(cve, d, fuentes))
    else:
        if motor in ("auto", "paquetes"):
            info = None
            m = MANUAL_RE.match(paquete.strip()) if paquete else None
            if m and debver.valid(m.group("ver")):
                info = (m.group("pkg").lower(), m.group("ver"), m.group("distro").lower())
            elif paquete:
                ctx.out.warn("«Paquete y versión» no tiene el formato «paquete versión distro» (p. ej. "
                             "openssh 1:9.6p1-3ubuntu13.5 ubuntu): se ignora.")
            if info is None:
                info = paquete_de_banner(banner)
            if info is None and obj.port and not obj.url:     # los servicios SSH se presentan al conectar
                b = ssh_banner(obj.host, obj.port, 3.0)
                if b:
                    results.write(d / "banner.txt", b + "\n")
                    info = paquete_de_banner(b)
            if info:
                ctx.out.info(f"Paquete {info[0]} {info[1]} ({info[2]})")
                pr.append(comprobar_paquete(cve, info[2], info[0], info[1], d))
            elif motor == "paquetes":
                pr.append(Prueba("paquetes de la distribución", NO_CONCLUYENTE,
                                 "no se conoce la versión exacta del paquete (el banner no la incluye): "
                                 "indícala en «Paquete y versión» o compruébalo en el equipo"))
        if motor in ("auto", "nuclei"):
            pr.append(run_nuclei(ctx, cve, obj, d, permitir_rce))
        if motor in ("auto", "nmap") and not _detenido(pr):
            pr.append(run_nmap(ctx, cve, obj, d))
        if motor == "auto":   # lo que no se pudo usar no cuenta como prueba si hubo otra útil
            utiles = [p for p in pr if p.estado != NO_CONCLUYENTE]
            if utiles:
                ver.pruebas = pr = utiles + [p for p in pr if p.estado == NO_CONCLUYENTE]
    ver.estado = combinar(pr)
    results.write(d / "veredicto.json", json.dumps(asdict(ver), ensure_ascii=False, indent=1))
    return ver


def _detenido(pr: list[Prueba]) -> bool:
    return any(p.detalle == "detenido por el usuario" for p in pr)


def mostrar(ctx: Context, ver: Veredicto) -> None:
    show = {CONFIRMADA: ctx.out.error, NO_APLICA: ctx.out.ok, NO_REPRODUCIDA: ctx.out.ok,
            NO_CONCLUYENTE: ctx.out.warn}[ver.estado]
    show(f"{ver.cve} en {ver.objetivo}: {ver.estado}  ({EXPLICACION[ver.estado]})")
    for p in ver.pruebas:
        if p.estado == NO_CONCLUYENTE:
            ctx.out.line(f"  ·  [{p.estado}] {p.motor}: {p.detalle}")
        else:
            ctx.out.check(p.estado != CONFIRMADA, f"[{p.estado}] {p.motor}: {p.detalle}")


# ---------------------------------------------------------------- acciones

def accion_cve(ctx: Context, v: dict) -> bool:
    cves = _cves(v.get("cve", ""))
    if not cves:
        ctx.out.error("CVE no válido. Formato: CVE-2024-6387 (varios separados por espacio o coma)")
        return False
    obj, problem = parse_objetivo(v.get("objetivo", ""))
    if obj is None:
        ctx.out.error(problem)
        return False
    if not obj.local and not scope.gate(ctx, obj.host, v, "verificacion"):
        return False
    if not obj.local and v.get("motor", "auto") in ("auto", "nuclei"):
        feeds.warn_if_stale(ctx)
    fuentes = osv.installed_sources() if obj.local else None
    vistos = []
    for cve in cves:
        d = results.new_dir("verificacion", f"{cve}_{'local' if obj.local else obj.texto}")
        ctx.out.title(f"{cve} · {obj.texto if not obj.local else 'este equipo'}")
        ver = verificar(ctx, cve, obj, d, motor=v.get("motor") or "auto", paquete=v.get("paquete") or "",
                        permitir_rce=bool(v.get("permitir_rce")), fuentes=fuentes)
        mostrar(ctx, ver)
        audit.record("verificacion", ver.objetivo, ver.estado, cve)
        vistos.append(ver)
        if _detenido(ver.pruebas):
            break
    if len(vistos) > 1:
        _tabla(ctx, vistos)
    ctx.out.info(f"Evidencias en {results.ROOT / 'verificacion'} (una carpeta por verificación)")
    return True


def _cves(text: str) -> list[str]:
    toks = [t for t in re.split(r"[\s,;]+", (text or "").strip()) if t]
    out = [osv.normalize_cve(t) for t in toks]
    return list(dict.fromkeys(out)) if out and all(out) and len(out) <= 50 else []


@dataclass
class Candidato:
    cve: str
    obj: Objetivo
    origen: str
    peso: float = 0.0
    banner: str = ""


def _sesion(modulo: str, v: dict) -> Optional[Path]:
    carpeta = (v.get("carpeta") or "").strip()
    if carpeta:
        if not SESION_RE.match(carpeta):
            return None
        d = results.ROOT / modulo / carpeta
        return d if d.is_dir() and not d.is_symlink() and d.resolve().parent == (results.ROOT / modulo).resolve() else None
    n = str(v.get("sesion") or "1").strip()
    sess = results.sessions(modulo, 50)
    if modulo == "escaneo":
        sess = [s for s in sess if any(not x.name.startswith("descubrimiento") for x in s.glob("*.xml"))]
    if modulo == "nuclei":
        sess = [s for s in sess if (s / "hallazgos.jsonl").exists()]
    if modulo == "informes":
        sess = [s for s in sess if (s / "hallazgos.json").exists()]
    if not n.isdigit() or not 1 <= int(n) <= len(sess):
        return None
    return sess[int(n) - 1]


def candidatos_nuclei(d: Path) -> list[Candidato]:
    out = []
    f = d / "hallazgos.jsonl"
    if not f.exists():
        return out
    for line in f.read_text(errors="replace").splitlines():
        try:
            h = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(h, dict):
            continue
        info = h.get("info") or {}
        cl = info.get("classification") or {}
        ids = cl.get("cve-id") or []
        ids = [ids] if isinstance(ids, str) else list(ids) if isinstance(ids, list) else []
        ids += CVE_ANY.findall(str(h.get("template-id", "")))
        target = str(h.get("matched-at") or h.get("host") or "")
        if target.startswith(("http://", "https://")):
            m = re.match(r"^(https?://[^/?#\s]+)", target)
            target = m.group(1) if m else target
        obj, _ = parse_objetivo(target)
        if obj is None or obj.local:
            continue
        sev = {"critical": 10, "high": 8, "medium": 5, "low": 3}.get(str(info.get("severity")), 1)
        for c in ids:
            cve = osv.normalize_cve(str(c))
            if cve:
                out.append(Candidato(cve, obj, f"nuclei {h.get('template-id', '')}", sev))
    return out


def candidatos_escaneo(d: Path) -> list[Candidato]:
    xmls = [x for x in sorted(d.glob("*.xml")) if not x.name.startswith("descubrimiento")]
    if not xmls:
        return []
    scan = nmapxml.parse(xmls[-1])
    out = []
    for h in scan.up():
        if not _host_ok(h.ip):
            continue
        for p in h.open_ports():
            banner = f"{p.product} {p.version}".strip()
            obj = Objetivo(h.ip, p.port, f"{'https' if p.is_tls else 'http'}://{h.ip}:{p.port}" if p.is_web else "")
            for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}(?:\.\d)?)", p.scripts.get("vulners", "")):
                out.append(Candidato(m.group(1).upper(), obj, f"vulners ({banner or p.label})", float(m.group(2)), banner))
            for sid, txt in p.scripts.items():
                if sid != "vulners" and "VULNERABLE" in txt:
                    for c in set(CVE_ANY.findall(txt)):
                        out.append(Candidato(c.upper(), obj, f"nmap {sid}", 9.0, banner))
        for sid, txt in h.scripts.items():
            if "VULNERABLE" in txt:
                for c in set(CVE_ANY.findall(txt)):
                    out.append(Candidato(c.upper(), Objetivo(h.ip), f"nmap {sid}", 9.0))
    return out


def candidatos_informe(d: Path) -> list[Candidato]:
    out = []
    peso = {"CRÍTICO": 10, "ALTO": 8, "MEDIO": 5, "BAJO": 3, "INFO": 1}
    for it in informes.read(d / "hallazgos.json"):
        if not _host_ok(it.host):
            continue
        for c in it.cves:
            cve = osv.normalize_cve(c)
            if cve:
                out.append(Candidato(cve, Objetivo(it.host, it.puerto), f"{it.fuente} {it.id} {it.nombre[:40]}",
                                     peso.get(it.severidad, 1) + (float(it.cvss) / 100 if _num(it.cvss) else 0),
                                     it.salida[:300]))
    return out


def _num(s: str) -> bool:
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False


ORIGENES = [("nuclei", "Último análisis de nuclei"), ("escaneo", "Último escaneo de nmap (CVE por versión: vulners)"),
            ("informes", "Informe de Nessus / OpenVAS importado")]


def candidatos(origen: str, d: Path) -> list[Candidato]:
    fn = {"nuclei": candidatos_nuclei, "escaneo": candidatos_escaneo, "informes": candidatos_informe}[origen]
    vistos: dict = {}
    for c in fn(d):
        k = (c.cve, c.obj.host, c.obj.port)
        if k not in vistos or c.peso > vistos[k].peso:
            vistos[k] = c
    return sorted(vistos.values(), key=lambda c: (-c.peso, c.obj.host, c.obj.port or 0, c.cve))


def accion_hallazgos(ctx: Context, v: dict) -> bool:
    origen = v.get("origen") or "nuclei"
    if origen not in dict(ORIGENES):
        ctx.out.error("Origen no válido")
        return False
    d = _sesion(origen, v)
    if d is None:
        ctx.out.error(f"No hay ese resultado de «{dict(ORIGENES)[origen]}» (mira «Resultados» o haz antes el análisis).")
        return False
    ctx.out.info(f"Hallazgos de: {d}")
    cands = candidatos(origen, d)
    if not cands:
        ctx.out.ok("Ese resultado no tiene hallazgos con CVE que verificar.")
        return True
    maximo = tooling.int_in(v.get("maximo"), 25, 1, 200)
    if len(cands) > maximo:
        ctx.out.warn(f"{len(cands)} hallazgos con CVE: se verifican los {maximo} más graves (cámbialo en «Máximo»).")
        cands = cands[:maximo]
    hosts = sorted({c.obj.host for c in cands})
    if not scope.gate(ctx, " ".join(hosts), v, "verificacion"):
        return False
    feeds.warn_if_stale(ctx)
    lote = results.new_dir("verificacion", f"lote_{origen}_{d.name[16:][:30]}")
    results.write(lote / "origen.txt", f"{origen}: {d}\n")
    vistos = []
    for i, c in enumerate(cands, 1):
        sub = lote / results.safe(f"{i:03d}_{c.cve}_{c.obj.texto}")
        sub.mkdir(mode=0o750)
        ctx.out.title(f"[{i}/{len(cands)}] {c.cve} · {c.obj.texto}  ({c.origen})")
        ver = verificar(ctx, c.cve, c.obj, sub, motor=v.get("motor") or "auto", banner=c.banner,
                        permitir_rce=bool(v.get("permitir_rce")))
        mostrar(ctx, ver)
        audit.record("verificacion", ver.objetivo, ver.estado, f"{c.cve} ({origen})")
        vistos.append(ver)
        if _detenido(ver.pruebas):
            ctx.out.warn("Verificación detenida: se guarda lo hecho hasta ahora.")
            break
    _tabla(ctx, vistos)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["estado", "cve", "objetivo", "motivo", "carpeta"])
    w.writerows(results.csv_safe([x.estado, x.cve, x.objetivo, x.motivo(), x.carpeta]) for x in vistos)
    results.write(lote / "verificacion.csv", buf.getvalue())
    ctx.out.info(f"Resumen en {lote / 'verificacion.csv'}; evidencias de cada hallazgo en su subcarpeta.")
    return True


def _tabla(ctx: Context, vistos: list[Veredicto]) -> None:
    from collections import Counter
    cnt = Counter(x.estado for x in vistos)
    ctx.out.title("Resultado: " + "  ·  ".join(f"{k}: {cnt[k]}" for k in ORDEN if cnt.get(k)))
    rows = [[x.estado, x.cve, x.objetivo[:40], x.motivo()[:220]] for x in sorted(vistos, key=lambda x: ORDEN[x.estado])]
    ctx.out.table(["Veredicto", "CVE", "Objetivo", "Motivo"], rows)


def accion_comprobaciones(ctx: Context, v: dict) -> bool:
    """Qué se lanzaría para un CVE, sin enviar nada."""
    cves = _cves(v.get("cve", ""))
    if not cves:
        ctx.out.error("CVE no válido. Formato: CVE-2024-6387")
        return False
    server, problem = interactsh()
    for cve in cves:
        ctx.out.title(cve)
        tpls = plantillas_cve(cve, bool(v.get("permitir_rce")), bool(server))
        if not system.has_cmd("nuclei"):
            ctx.out.line("  nuclei: no está instalado")
        elif nuclei_dir() is None:
            ctx.out.line("  nuclei: plantillas sin descargar")
        elif not tpls:
            ctx.out.line("  nuclei: no hay plantilla para este CVE")
        for t in tpls:
            ctx.out.check(not t.motivo, f"nuclei {t.path}" + (f" — no se lanza: {t.motivo}" if t.motivo else " — se lanza"))
        nse = scripts_cve(cve)
        if not system.has_cmd("nmap"):
            ctx.out.line("  nmap: no está instalado")
        elif not nse:
            ctx.out.line("  nmap: no hay script NSE para este CVE")
        for name, motivo in nse:
            ctx.out.check(not motivo, f"nmap --script {name}" + (f" — no se lanza: {motivo}" if motivo else " — se lanza"))
        ctx.out.line("  paquetes: aviso de Ubuntu/Debian en OSV (se descarga el aviso de este CVE, nada más)")
    if problem:
        ctx.out.warn(problem)
    elif not server:
        ctx.out.info("Sin servidor interactsh propio: las plantillas que lo necesitan no se lanzan (ver ayuda).")
    return True


def accion_ver(ctx: Context, v: dict) -> bool:
    sess = results.sessions("verificacion", 40)
    if not sess:
        ctx.out.info("Todavía no hay verificaciones guardadas.")
        return True
    rows = []
    for s in sess:
        files = [s / "veredicto.json"] if (s / "veredicto.json").exists() else sorted(s.glob("*/veredicto.json"))
        for f in files[:50]:
            try:
                data = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            n = s.name
            rows.append([f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}", str(data.get("estado", "?")),
                         str(data.get("cve", "?")), str(data.get("objetivo", "?"))[:40]])
    ctx.out.table(["Fecha", "Veredicto", "CVE", "Objetivo"], rows[:200])
    ctx.out.info(f"Detalle y evidencias en {results.ROOT / 'verificacion'} o con la tecla g (Resultados).")
    return True


def _confirm_cve(v: dict) -> str:
    obj, _ = parse_objetivo(v.get("objetivo", ""))
    if obj is not None and obj.local:
        return ""        # solo lee los paquetes instalados y descarga el aviso
    motor = v.get("motor") or "auto"
    partes = []
    if motor in ("auto", "paquetes"):
        partes.append("lee el banner del servicio y compara la versión con los avisos de la distribución")
    if motor in ("auto", "nuclei"):
        partes.append("lanza las plantillas seguras de nuclei de ese CVE (10 peticiones/s como máximo)")
    if motor in ("auto", "nmap"):
        partes.append("lanza los scripts NSE «vuln» y «safe» de ese CVE")
    return (f"Se va a verificar {v.get('cve', '').upper()} en {v.get('objetivo', '')}: " + "; ".join(partes)
            + ".\nNo se explota nada ni se prueban contraseñas. Cada orden se muestra antes de lanzarla. "
            "¿Tienes autorización?")


class Verificacion(Module):
    full = True
    id = "verificacion"
    name = "Verificar vulnerabilidades"
    category = "Ciberseguridad"
    summary = "Confirma o descarta de forma segura los CVE que marcan los análisis (falsos positivos)"
    requires: list = []
    optional = [cmd("nmap", debian="nmap", rhel="nmap", suse="nmap", arch="nmap", label="nmap (scripts NSE)"),
                cmd("nuclei", debian="nuclei", arch="nuclei", label="nuclei (plantillas por CVE)")]
    help = """\
# Verificación de vulnerabilidades

> Solo contra sistemas propios o con autorización por escrito. Pasa por la barandilla de alcance.

Los escáneres marcan muchos CVE **por el número de versión**. Este módulo comprueba, para cada CVE,
si la deficiencia **se cumple de verdad**, con pruebas que **no explotan nada**: no dan acceso, no
cambian nada en el objetivo y no prueban contraseñas.

## Veredictos

- **CONFIRMADA**: la deficiencia se cumple (una prueba segura lo ha visto, o la versión del paquete
  es anterior a la corrección).
- **NO APLICA**: no afecta; normalmente porque la distribución ya publicó el parche con el mismo
  número de versión (*backport*).
- **NO REPRODUCIDA**: la prueba segura se lanzó y el servicio no respondió como vulnerable.
- **NO CONCLUYENTE**: no hay forma segura de comprobarlo o no se pudo probar. Revisar a mano.

## Cómo comprueba

1. **Paquetes de la distribución (backports).** Compara la versión del paquete con la versión en la
   que Ubuntu o Debian corrigió el CVE (avisos OSV). La versión sale del banner cuando lo incluye
   (OpenSSH en Ubuntu/Debian: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`), de lo que indiques en «Paquete y
   versión» o, con el objetivo `local`, de los paquetes instalados en este equipo. Solo sale a
   internet el identificador del CVE (nunca equipos ni resultados); se puede desactivar con
   `[verificacion] consultar_osv = false`.
2. **nuclei**: solo las plantillas de ese CVE que son seguras. Nunca las etiquetadas `dos`, `fuzz`,
   `intrusive`, `brute-force` o `default-login`, ni las de tipo `code`, `headless`, `javascript` o
   `file`, a 10 peticiones por segundo como máximo. Las que confirman ejecutando una orden inocua en
   el objetivo (`rce`) solo se lanzan si marcas «Permitir plantillas rce».
3. **nmap**: solo los scripts NSE de ese CVE que nmap clasifica a la vez como `vuln` y `safe`.

## Pruebas «fuera de banda» (interactsh)

Algunas vulnerabilidades (Log4Shell, SSRF, ejecución ciega) solo se confirman si el objetivo se
conecta de vuelta a un servidor de escucha (*interactsh*). Por defecto **esas plantillas no se lanzan**,
porque nuclei usaría servidores públicos de internet. Si tienes un interactsh **propio dentro de la red
interna**, indícalo en la configuración y se usarán:

```ini
[verificacion]
interactsh_servidor = https://oast.interno.empresa.local
```

Se rechazan los servidores públicos y los que no resuelven a una dirección interna o autorizada.

## Acciones

- **Verificar un CVE**: uno o varios CVE sobre un objetivo (`10.0.0.5:22`, una URL o `local`).
- **Verificar hallazgos de un análisis**: toma los CVE del último análisis de nuclei, del último
  escaneo (vulners) o de un informe de Nessus/OpenVAS importado y los verifica uno a uno, los más
  graves primero. También desde **Resultados** (tecla g) con el botón *Verificar hallazgos*.
- **¿Afecta a este equipo?**: los CVE indicados contra los paquetes instalados aquí.
- **Qué comprobaciones hay**: qué plantillas y scripts se lanzarían para un CVE, sin enviar nada.
- **Verificaciones guardadas**.

Cada verificación se guarda en su propia carpeta (`resultados/verificacion/`), con el veredicto, las
órdenes lanzadas y las evidencias. El análisis de origen solo se lee: no se modifica.
"""

    def actions(self):
        ok = scope.ok_param()
        rce = Param("permitir_rce", "Permitir plantillas rce (confirman ejecutando una orden inocua)", "bool", False,
                    required=False, advanced=True,
                    help="Desmarcado por defecto: esas plantillas ejecutan algo (p. ej. un «echo») en el objetivo.")
        motor = Param("motor", "Comprobaciones", "choice", "auto", choices=MOTORES)
        cve = Param("cve", "CVE", help="Ej.: CVE-2024-6387 (varios separados por espacio o coma)")
        return [
            Action("cve", "Verificar un CVE", accion_cve, params=[
                cve, Param("objetivo", "Objetivo", help="equipo, equipo:puerto, URL o «local» (este equipo)"),
                motor, Param("paquete", "Paquete y versión (opcional)", required=False, advanced=True,
                             help="Si conoces la versión exacta del paquete: «openssh 1:9.6p1-3ubuntu13.5 ubuntu»"),
                rce, ok], confirm=_confirm_cve,
                help="Comprueba si el CVE se cumple en ese objetivo con pruebas seguras."),
            Action("hallazgos", "Verificar hallazgos de un análisis", accion_hallazgos, params=[
                Param("origen", "Hallazgos de", "choice", "nuclei", choices=ORIGENES),
                Param("sesion", "Cuál (1 = el último)", "int", 1, required=False),
                Param("maximo", "Máximo de hallazgos a verificar", "int", 25, required=False),
                motor, rce, ok,
                Param("carpeta", "Carpeta del resultado (la rellena la pantalla de Resultados)", required=False,
                      advanced=True)],
                confirm=lambda v: (f"Se verificarán los CVE de «{dict(ORIGENES).get(v.get('origen'), '?')}» con pruebas "
                                   "seguras contra sus equipos (cada orden se muestra antes). ¿Tienes autorización?"),
                help="Toma los CVE de un análisis anterior y los verifica uno a uno, los más graves primero."),
            Action("local", "¿Afecta a este equipo?", lambda c, v: accion_cve(c, {**v, "objetivo": "local"}),
                   params=[cve], help="Compara los paquetes instalados con los avisos de la distribución."),
            Action("comprobaciones", "Qué comprobaciones hay para un CVE", accion_comprobaciones,
                   params=[cve, rce], help="Muestra qué se lanzaría, sin enviar nada a ningún equipo."),
            Action("ver", "Verificaciones guardadas", accion_ver),
        ]
