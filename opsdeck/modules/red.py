"""Red: interfaces, rutas, DNS, conexiones activas y comprobación de conectividad."""

from __future__ import annotations

import socket
import time
from collections import Counter
from pathlib import Path

from ..core import system
from ..core.catalog import Action, Context, Module, Param, cmd


def interfaces(ctx: Context, v: dict) -> bool:
    r = system.run(["ip", "-br", "addr"], c_locale=True)
    ctx.out.title("Interfaces")
    ctx.out.table(["Interfaz", "Estado", "Direcciones"],
                  [[f[0], f[1], " ".join(f[2:])] for f in (l.split() for l in r.out.splitlines()) if len(f) >= 2])
    r = system.run(["ip", "route"], c_locale=True)
    ctx.out.title("Rutas")
    for line in r.out.splitlines():
        ctx.out.line(("  ► " if line.startswith("default") else "    ") + line)
    ctx.out.title("DNS")
    if system.has_cmd("resolvectl"):
        r = system.run(["resolvectl", "dns"], c_locale=True)
        if r.ok and r.out.strip():
            for line in r.out.splitlines():
                ctx.out.line("    " + line)
            return True
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith(("nameserver", "search", "domain")):
                ctx.out.line("    " + line)
    except OSError:
        ctx.out.warn("No se pudo leer /etc/resolv.conf")
    return True


def conexiones(ctx: Context, v: dict) -> bool:
    if not system.has_cmd("ss"):
        ctx.out.warn("Falta 'ss' (paquete iproute2).")
        return False
    r = system.run(["ss", "-tnpH", "state", "established"], c_locale=True)
    rows, peers = [], Counter()
    for line in r.out.splitlines():
        f = line.split()
        if len(f) < 4:
            continue
        local, peer = f[2], f[3]
        proc = line.split('users:(("', 1)[1].split('"', 1)[0] if 'users:(("' in line else "?"
        lport = local.rpartition(":")[2]
        pip = peer.rpartition(":")[0].strip("[]").removeprefix("::ffff:")
        peers[pip] += 1
        rows.append([proc, lport, peer.removeprefix("[::ffff:").replace("]", "")])
    if not rows:
        ctx.out.info("No hay conexiones TCP establecidas.")
        return True
    ctx.out.title(f"{len(rows)} conexiones TCP establecidas")
    ctx.out.table(["Equipo remoto", "Conexiones"], [[k, str(n)] for k, n in peers.most_common(15)])
    ctx.out.table(["Proceso", "Puerto local", "Remoto"], sorted(rows)[:60])
    return True


def conectividad(ctx: Context, v: dict) -> bool:
    host, port = v["destino"].strip(), str(v.get("puerto") or "").strip()
    o = ctx.out
    try:
        t0 = time.time()
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        o.check(True, f"DNS: {host} → {', '.join(ips)} ({(time.time() - t0) * 1000:.0f} ms)")
    except socket.gaierror as e:
        o.check(False, f"DNS: no se resuelve '{host}' ({e.strerror})")
        return False
    if system.has_cmd("ping"):
        r = system.run(["ping", "-c", "3", "-W", "2", host], c_locale=True, timeout=15)
        summary = next((l for l in r.out.splitlines() if "packet loss" in l), "")
        rtt = next((l.split("=")[1].strip() for l in r.out.splitlines() if "min/avg" in l), "")
        o.check(r.ok, f"Ping: {summary or 'sin respuesta'}" + (f" · rtt {rtt}" if rtt else ""))
        if not r.ok:
            o.info("Muchos equipos y firewalls no responden a ping; no significa que estén apagados.")
    if port:
        if not port.isdigit():
            o.error("El puerto debe ser un número")
            return False
        try:
            t0 = time.time()
            with socket.create_connection((host, int(port)), timeout=5):
                o.check(True, f"Puerto {port}/tcp: ABIERTO ({(time.time() - t0) * 1000:.0f} ms)")
        except socket.timeout:
            o.check(False, f"Puerto {port}/tcp: sin respuesta (filtrado por un firewall o equipo apagado)")
        except ConnectionRefusedError:
            o.check(False, f"Puerto {port}/tcp: CERRADO (el equipo responde pero no hay servicio)")
        except OSError as e:
            o.check(False, f"Puerto {port}/tcp: error ({e.strerror})")
    if system.has_cmd("ip"):
        r = system.run(["ip", "route", "get", ips[0]], c_locale=True)
        if r.ok:
            o.info("Ruta usada: " + r.out.splitlines()[0])
    return True


class Red(Module):
    id = "red"
    name = "Red"
    category = "Sistemas"
    summary = "Interfaces, rutas, DNS, conexiones activas y comprobar conectividad"
    requires = [cmd("ip", debian="iproute2", rhel="iproute", suse="iproute2", arch="iproute2")]
    help = """\
# Red

- **Interfaces, rutas y DNS**: direcciones IP, puerta de enlace (marcada con ►) y servidores DNS.
- **Conexiones activas**: con qué equipos está hablando ahora este equipo y qué programa lo hace.
- **Comprobar conectividad**: para el típico "no llego a tal servidor". Comprueba por orden
  el **DNS**, el **ping** y, si indicas un puerto, si ese **puerto** está abierto, cerrado o filtrado.

| Resultado del puerto | Qué significa |
|---|---|
| ABIERTO | Hay un servicio escuchando y se llega a él |
| CERRADO | El equipo responde, pero en ese puerto no hay nada |
| Sin respuesta | Un firewall lo bloquea, o el equipo está apagado o inaccesible |

Los puertos en escucha de este equipo están en *Sistema › Puertos en escucha* y el firewall en su módulo.
"""

    def actions(self):
        return [
            Action("interfaces", "Interfaces, rutas y DNS", interfaces),
            Action("conexiones", "Conexiones activas", conexiones),
            Action("conectividad", "Comprobar conectividad", conectividad, params=[
                Param("destino", "Equipo (nombre o IP)", help="Ej.: srvdatos01, 192.168.0.250, google.com"),
                Param("puerto", "Puerto TCP", required=False, help="Ej.: 445 (SMB), 3389 (RDP), 443 (web)")]),
        ]
