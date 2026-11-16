"""Tráfico de red: capturar, analizar capturas y descubrir equipos de forma pasiva (sin enviar nada).

El análisis resume metadatos (quién habla con quién, puertos, consultas DNS, protocolos sin cifrar,
señales de suplantación ARP). No extrae contenido ni credenciales de los paquetes."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from ..core import audit, results, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream

FLOW = re.compile(r"^\S+ IP6? (\S+?)\.(\d+) > (\S+?)\.(\d+): (\w+)")
NOPORT = re.compile(r"^\S+ IP6? (\S+) > (\S+): (\w+)")
DNSQ = re.compile(r"\s(A|AAAA|PTR|TXT|MX|SRV|ANY)\? (\S+?)\.? \(")
ARP_E = re.compile(r"^\S+ ([0-9a-f:]{17}) > .*?(?:tell (\S+?),|Reply (\S+) is-at)")
FILTER_RE = re.compile(r"^[A-Za-z0-9 .:/()\[\]!=<>&|_-]*$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,20}$")
CLEARTEXT = {21: "FTP", 23: "Telnet", 25: "SMTP", 69: "TFTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
             161: "SNMP v1/v2", 389: "LDAP sin TLS", 513: "rlogin", 514: "rsh/syslog"}


def interfaces() -> list[str]:
    r = system.run(["ip", "-br", "link"], c_locale=True)
    return [l.split()[0].split("@")[0] for l in r.out.splitlines() if l.split()] or ["any"]


def summarize(flow_lines: list[str], dns_lines: list[str], arp_lines: list[str]) -> dict:
    talkers, pairs, ports, protos = Counter(), Counter(), Counter(), Counter()
    clear: dict[str, Counter] = defaultdict(Counter)
    for line in flow_lines:
        m = FLOW.match(line)
        if m and not m.group(5).lower().startswith(("icmp", "igmp")):   # sin puertos: no es un flujo
            src, sp, dst, dp, proto = m.group(1), int(m.group(2)), m.group(3), int(m.group(4)), m.group(5).lower()
            talkers[src] += 1
            pairs[(src, dst)] += 1
            service = min(sp, dp)
            ports[(proto, service)] += 1
            protos[proto] += 1
            if service in CLEARTEXT:
                server, client = (dst, src) if dp == service else (src, dst)
                clear[CLEARTEXT[service]][f"{client} → {server}"] += 1
            continue
        m = NOPORT.match(line)
        if m:
            talkers[m.group(1)] += 1
            protos[m.group(3).lower()] += 1
    queries = Counter()
    for line in dns_lines:
        m = DNSQ.search(line)
        if m:
            queries[m.group(2).lower()] += 1
    macs: dict[str, set] = defaultdict(set)
    for line in arp_lines:
        m = ARP_E.match(line)
        if m:
            ip = m.group(2) or m.group(3)
            if ip and ip != "0.0.0.0":
                macs[ip].add(m.group(1))
    return {"paquetes": len(flow_lines), "talkers": talkers, "pares": pairs, "puertos": ports, "protocolos": protos,
            "sin_cifrar": clear, "dns": queries, "macs": macs}


def read_pcap(pcap: Path) -> dict:
    base = ["tcpdump", "-nn", "-r", str(pcap)]
    flows = system.run([*base, "-q"], c_locale=True, timeout=300).out.splitlines()
    dns = system.run([*base, "port", "53"], c_locale=True, timeout=300).out.splitlines()
    arp = system.run([*base, "-e", "arp"], c_locale=True, timeout=300).out.splitlines()
    return summarize(flows, dns, arp)


def show(ctx: Context, s: dict) -> list[str]:
    o, report = ctx.out, []
    o.title(f"{s['paquetes']} paquetes · protocolos: " + "  ".join(f"{k}({v})" for k, v in s["protocolos"].most_common(6)))
    o.table(["Equipo que más envía", "Paquetes"], [[k, str(v)] for k, v in s["talkers"].most_common(10)])
    o.table(["Origen", "Destino", "Paquetes"], [[a, b, str(v)] for (a, b), v in s["pares"].most_common(10)])
    o.table(["Protocolo", "Puerto de servicio", "Paquetes"],
            [[p, str(port), str(v)] for (p, port), v in s["puertos"].most_common(12)])
    if s["dns"]:
        o.title(f"Consultas DNS ({len(s['dns'])} nombres distintos)")
        o.table(["Nombre", "Veces"], [[k, str(v)] for k, v in s["dns"].most_common(15)])
        odd = [n for n in s["dns"] if len(n) > 60 or max((len(x) for x in n.split(".")), default=0) > 40]
        if odd:
            o.check(False, f"[MEDIO] Nombres DNS anormalmente largos (posible túnel DNS): {', '.join(odd[:3])}")
            report.append("DNS sospechoso: " + ", ".join(odd))
    if s["sin_cifrar"]:
        o.title("Protocolos sin cifrar vistos en la red")
        for proto, who in s["sin_cifrar"].items():
            o.check(False, f"{proto}: " + "; ".join(f"{k} ({v})" for k, v in who.most_common(5)))
            report.append(f"Sin cifrar {proto}: " + "; ".join(who))
        o.info("Lo que viaja por estos protocolos (incluidas contraseñas) puede leerlo cualquiera en la red: "
               "sustitúyelos por sus versiones cifradas.")
    dup = {ip: m for ip, m in s["macs"].items() if len(m) > 1}
    if dup:
        o.title("Posible suplantación ARP")
        for ip, m in dup.items():
            o.check(False, f"[ALTO] {ip} aparece con varias MAC: {', '.join(sorted(m))}")
            report.append(f"ARP: {ip} con varias MAC {sorted(m)}")
        o.info("Puede ser un ataque de intermediario (ARP spoofing) o un equipo con alta disponibilidad/varias tarjetas.")
    return report


def _iface(ctx, v) -> str:
    i = (v.get("interfaz") or "").strip()
    if not IFACE_RE.match(i) or (i != "any" and i not in interfaces()):
        ctx.out.error(f"Interfaz no válida. Disponibles: {', '.join(interfaces())}, any")
        return ""
    return i


def _capture(ctx, iface: str, secs: int, flt: str, pcap: Path, label: str) -> bool:
    args = ["timeout", "--signal=INT", str(secs), "tcpdump", "-i", iface, "-nn", "-U", "-w", str(pcap), "-c", "500000"]
    if flt:
        args.append(flt)
    ctx.out.info(f"Capturando en {iface} durante {secs} s (s = detener)...")
    rc, _ = stream(ctx, args, accion=f"trafico_{label}", objetivo=iface, detalle=f"segundos={secs} filtro={flt or '-'}",
                   keep=6)
    if not pcap.exists() or pcap.stat().st_size <= 24:
        ctx.out.warn("No se capturó ningún paquete (revisa la interfaz y el filtro).")
        return False
    pcap.chmod(0o600)
    return True


def capturar(ctx: Context, v: dict) -> bool:
    iface = _iface(ctx, v)
    if not iface:
        return False
    flt = (v.get("filtro") or "").strip()
    if not FILTER_RE.match(flt):
        ctx.out.error("Filtro con caracteres no permitidos. Ej.: host 192.168.0.10 and port 443")
        return False
    secs = max(5, min(int(v.get("segundos") or 60), 3600))
    d = results.new_dir("trafico", f"captura_{iface}")
    pcap = d / "captura.pcap"
    if not _capture(ctx, iface, secs, flt, pcap, "capturar"):
        return False
    report = show(ctx, read_pcap(pcap))
    results.write(d / "hallazgos.txt", "\n".join(report) + "\n")
    ctx.out.info(f"Captura guardada en {pcap} (ábrela con Wireshark para el detalle).")
    return True


def analizar(ctx: Context, v: dict) -> bool:
    p = (v.get("fichero") or "").strip()
    if not p:
        caps = [c for s in results.sessions("trafico") for c in s.glob("*.pcap")]
        if not caps:
            ctx.out.error("No hay capturas guardadas: indica la ruta de un fichero .pcap o haz una captura.")
            return False
        pcap = caps[0]
    else:
        pcap = Path(p)
    if not pcap.is_file():
        ctx.out.error(f"No existe {pcap}")
        return False
    ctx.out.info(f"Analizando {pcap}...")
    show(ctx, read_pcap(pcap))
    audit.record("trafico_analizar", str(pcap), "OK")
    return True


def pasivo(ctx: Context, v: dict) -> bool:
    iface = _iface(ctx, v)
    if not iface:
        return False
    secs = max(10, min(int(v.get("segundos") or 120), 3600))
    d = results.new_dir("trafico", f"pasivo_{iface}")
    pcap = d / "pasivo.pcap"
    if not _capture(ctx, iface, secs, "arp or broadcast or multicast", pcap, "pasivo"):
        return False
    arp = system.run(["tcpdump", "-nn", "-e", "-r", str(pcap), "arp"], c_locale=True).out.splitlines()
    macs = summarize([], [], arp)["macs"]
    rows = [[ip, ", ".join(sorted(m))] for ip, m in sorted(macs.items(), key=lambda x: [int(p) if p.isdigit() else 0
                                                                                      for p in x[0].split(".")])]
    ctx.out.title(f"{len(rows)} equipos vistos sin enviar ni un paquete")
    ctx.out.table(["IP", "MAC"], rows)
    results.write(d / "hosts_vistos.txt", "\n".join(r[0] for r in rows) + "\n")
    ctx.out.info(f"Lista en {d / 'hosts_vistos.txt'} (sirve como objetivo de un escaneo). "
                 "Cuanto más tiempo escuches, más equipos aparecerán.")
    return True


class Trafico(Module):
    id = "trafico"
    name = "Tráfico de red"
    category = "Ciberseguridad"
    full = True
    summary = "Capturar y analizar tráfico; descubrir equipos de forma pasiva"
    requires = [cmd("tcpdump", debian="tcpdump", rhel="tcpdump", suse="tcpdump", arch="tcpdump"),
                cmd("ip", debian="iproute2", rhel="iproute", suse="iproute2", arch="iproute2")]
    help = """\
# Tráfico de red

> Solo en redes propias o con autorización por escrito. Capturar tráfico afecta a la privacidad
> de quien usa la red: hazlo dentro del procedimiento de tu organización.

Análisis **pasivo**: no envía nada a la red, solo escucha.

- **Capturar y resumir**: graba el tráfico de una interfaz durante unos segundos (con filtro opcional)
  y lo resume: quién habla más, con quién, por qué puertos, qué nombres DNS se consultan, y avisos:
  - **protocolos sin cifrar** (Telnet, FTP, HTTP, LDAP sin TLS, SNMP v1/v2...) y entre qué equipos;
  - **posible suplantación ARP** (una IP con varias MAC);
  - nombres DNS anormalmente largos (posible túnel DNS).
- **Analizar una captura**: lo mismo sobre un `.pcap` existente (propio o recibido de otro equipo).
- **Descubrimiento pasivo**: lista los equipos de la red escuchando ARP y difusión, sin escanear.
  Útil cuando no quieres hacer ruido o hay equipos frágiles (industriales, médicos).

El resumen usa solo metadatos: no muestra el contenido de los paquetes. La captura completa queda
guardada (solo root) para abrirla con Wireshark.

**Filtros** (sintaxis de tcpdump): `host 192.168.0.10`, `port 443`, `net 10.0.0.0/8`,
`host 192.168.0.10 and not port 22`.

Nota: en una red con switches solo verás tu propio tráfico y la difusión, salvo que captures en un
puerto espejo (SPAN) o en el propio servidor o firewall.
"""

    def actions(self):
        iface = Param("interfaz", "Interfaz", suggest=interfaces, default=next(
            (i for i in interfaces() if i != "lo"), "any"), help="Ej.: eth0. 'any' = todas")
        return [
            Action("capturar", "Capturar y resumir", capturar, params=[
                iface, Param("segundos", "Duración (segundos)", "int", 60),
                Param("filtro", "Filtro (opcional)", required=False, help="Ej.: host 192.168.0.10 and port 443")]),
            Action("analizar", "Analizar una captura", analizar, params=[
                Param("fichero", "Fichero .pcap (vacío = última captura)", required=False)]),
            Action("pasivo", "Descubrimiento pasivo", pasivo, params=[
                iface, Param("segundos", "Tiempo de escucha (segundos)", "int", 120)]),
        ]
