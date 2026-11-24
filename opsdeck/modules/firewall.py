"""Firewall: estado y reglas con ufw (Debian/Ubuntu/Kali) o firewalld (RHEL/SUSE).
Al activarlo, primero deja abiertos SSH y escritorio remoto para no quedarse fuera."""

from __future__ import annotations

import ipaddress
import re

from ..core import packages, system
from ..core.catalog import AVAILABLE, INSTALLABLE, UNAVAILABLE, Action, Context, Module, Param, Status
from ..core.ops import apply

PORT_RE = re.compile(r"^\d{1,5}(:\d{1,5})?$")


def backend() -> str:
    if system.has_cmd("ufw"):
        return "ufw"
    if system.has_cmd("firewall-cmd"):
        return "firewalld"
    return ""


def _check(ctx, port: str, source: str) -> bool:
    if not PORT_RE.match(port) or any(int(p) > 65535 or int(p) == 0 for p in port.split(":")):
        ctx.out.error("Puerto no válido: un número (443) o un rango (8000:8100)")
        return False
    if source:
        try:
            ipaddress.ip_network(source, strict=False)
        except ValueError:
            ctx.out.error("Origen no válido: una IP (192.168.0.10) o una red (192.168.0.0/24)")
            return False
    return True


def active() -> bool:
    if backend() == "ufw":
        return "Status: active" in system.run(["ufw", "status"], c_locale=True).out
    if backend() == "firewalld":
        return system.run(["firewall-cmd", "--state"], c_locale=True).out.strip() == "running"
    return False


def _fw() -> list[str]:
    """firewall-cmd --permanent solo funciona con firewalld en marcha; parado, se usa
    firewall-offline-cmd, que edita la misma configuración permanente."""
    if active() or not system.has_cmd("firewall-offline-cmd"):
        return ["firewall-cmd", "--permanent"]
    return ["firewall-offline-cmd"]


def _reload(ctx) -> bool:
    if not active():
        return True
    return apply(ctx, "firewall_recargar", "firewalld", ["firewall-cmd", "--reload"], quiet=True)


def estado(ctx: Context, v: dict) -> bool:
    b = backend()
    ctx.out.title(f"Firewall ({b})")
    if b == "ufw":
        r = system.run(["ufw", "status", "verbose"], c_locale=True)
    else:
        r = system.run(["firewall-cmd", "--list-all"], c_locale=True) if active() else \
            system.run(["firewall-cmd", "--state"], c_locale=True)
    for line in r.text.splitlines():
        ctx.out.line(line)
    if not active():
        ctx.out.warn("El firewall está DESACTIVADO: todos los puertos en escucha son accesibles desde la red.")
        ctx.out.info("Usa 'Activar firewall' (deja abiertos SSH y escritorio remoto antes de activarlo).")
    return True


def permitir(ctx: Context, v: dict) -> bool:
    port, proto, src = v["puerto"].strip(), v["protocolo"], (v.get("origen") or "").strip()
    if not _check(ctx, port, src):
        return False
    target = f"{port}/{proto}" + (f" desde {src}" if src else "")
    if backend() == "ufw":
        args = ["ufw", "allow"] + (["from", src, "to", "any"] if src else []) + ["port", port, "proto", proto]
        ok = apply(ctx, "firewall_permitir", target, args)
    else:
        if src:
            rule = f'rule family="ipv{ipaddress.ip_network(src, strict=False).version}" source address="{src}" ' \
                   f'port port="{port.replace(":", "-")}" protocol="{proto}" accept'
            ok = apply(ctx, "firewall_permitir", target, _fw() + [f"--add-rich-rule={rule}"])
        else:
            ok = apply(ctx, "firewall_permitir", target, _fw() + [f"--add-port={port.replace(':', '-')}/{proto}"])
        ok = ok and _reload(ctx)
    if ok:
        ctx.out.ok(f"Permitido {target}.")
        if not active():
            ctx.out.warn("El firewall está desactivado: la regla se aplicará cuando lo actives.")
    return ok


def reglas_ufw() -> list[tuple[str, str]]:
    r = system.run(["ufw", "status", "numbered"], c_locale=True)
    out = []
    for line in r.out.splitlines():
        m = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def quitar(ctx: Context, v: dict) -> bool:
    if backend() == "ufw":
        rules = reglas_ufw()
        num = v["regla"].strip()
        match = next((r for r in rules if r[0] == num), None)
        if not match:
            ctx.out.error("No existe esa regla. Reglas actuales:")
            for n, r in rules:
                ctx.out.line(f"  [{n}] {r}")
            return False
        remote = {p for p, _ in _remote_ports()}
        rule_ports = set(re.findall(r"\b(\d{1,5})(?:/(?:tcp|udp))?\b", match[1].split(" ALLOW")[0]))
        if rule_ports & remote and "ALLOW" in match[1] and not v.get("si_acceso_remoto"):
            ctx.out.error(f"La regla [{num}] {match[1]} es el acceso remoto de este equipo: quitarla puede dejarte "
                          "fuera. Si es lo que quieres, marca «Sí, quitar el acceso remoto».")
            return False
        ok = apply(ctx, "firewall_quitar", match[1], ["ufw", "--force", "delete", num])
    else:
        spec = v["regla"].strip()
        if not re.match(r"^\d{1,5}(-\d{1,5})?/(tcp|udp)$", spec):
            ctx.out.error("Indica el puerto como en la lista: 8080/tcp")
            return False
        if spec.split("/")[0] in {p for p, _ in _remote_ports()} and not v.get("si_acceso_remoto"):
            ctx.out.error(f"{spec} es el acceso remoto de este equipo (SSH/escritorio remoto): quitarlo puede "
                          "dejarte fuera. Si es lo que quieres, marca «Sí, quitar el acceso remoto».")
            return False
        ok = apply(ctx, "firewall_quitar", spec, _fw() + [f"--remove-port={spec}"]) and _reload(ctx)
    if ok:
        ctx.out.ok("Regla eliminada.")
    return ok


def listar_reglas(ctx: Context, v: dict) -> bool:
    if backend() == "ufw":
        rules = reglas_ufw()
        if not rules:
            ctx.out.info("No hay reglas (o el firewall está desactivado: ufw solo numera reglas activo).")
            r = system.run(["ufw", "show", "added"], c_locale=True)
            for line in r.out.splitlines():
                ctx.out.line(line)
            return True
        ctx.out.table(["Nº", "Regla"], [[n, r] for n, r in rules])
        ctx.out.info("Para quitar una, usa su número en 'Quitar una regla'.")
    else:
        r = system.run(["firewall-cmd", "--list-ports"], c_locale=True)
        ctx.out.line("Puertos abiertos: " + (r.out.strip() or "(ninguno)"))
        r = system.run(["firewall-cmd", "--list-services"], c_locale=True)
        ctx.out.line("Servicios permitidos: " + (r.out.strip() or "(ninguno)"))
    return True


def _listening() -> list[tuple[str, str]]:
    """(puerto, proceso) de los sockets TCP en escucha."""
    if not system.has_cmd("ss"):
        return []
    out = []
    for line in system.run(["ss", "-ltnpH"], c_locale=True).out.splitlines():
        f = line.split()
        if len(f) > 3:
            m = re.search(r'users:\(\("([^"]+)"', line)
            out.append((f[3].rpartition(":")[2], m.group(1) if m else ""))
    return out


def _sshd_ports() -> set[str]:
    ports = set()
    if system.has_cmd("sshd"):
        for line in system.run([system.which("sshd"), "-T"], c_locale=True).out.splitlines():
            if line.startswith("port "):
                ports.add(line.split()[1])
    return ports


def _xrdp_ports() -> set[str]:
    try:
        text = open("/etc/xrdp/xrdp.ini", encoding="utf-8", errors="replace").read()
    except OSError:
        return set()
    m = re.search(r"^\s*port\s*=\s*(?:tcp6?://)?[^:\s]*:?(\d{1,5})\s*$", text, re.M)
    return {m.group(1)} if m else set()


def _remote_ports() -> list[tuple[str, str]]:
    """Puertos por los que se administra este equipo en remoto: los que configuran sshd y xrdp y los
    que escuchan esos procesos (no se supone el 22: sshd puede estar en el 2222)."""
    listen = _listening()
    ssh = _sshd_ports() | {p for p, proc in listen if proc == "sshd" or (proc == "systemd" and p == "22")}
    if not ssh and system.has_cmd("sshd"):
        ssh = {"22"}
    rdp = _xrdp_ports() | {p for p, proc in listen if proc == "xrdp"}
    if not rdp and system.has_cmd("xrdp"):
        rdp = {"3389"}
    return [(p, "SSH") for p in sorted(ssh, key=int)] + [(p, "escritorio remoto") for p in sorted(rdp - ssh, key=int)]


def _remote_peers(ports: set[str]) -> set[str]:
    """IP de origen de las sesiones remotas abiertas ahora en esos puertos."""
    if not system.has_cmd("ss") or not ports:
        return set()
    peers = set()
    for line in system.run(["ss", "-tnH", "state", "established"], c_locale=True).out.splitlines():
        f = line.split()
        if len(f) >= 4 and f[2].rpartition(":")[2] in ports:
            peers.add(f[3].rpartition(":")[0].strip("[]").removeprefix("::ffff:"))
    return peers


def _locks_out(origin: str, ports: set[str]) -> list[str]:
    """Sesiones remotas abiertas que quedarían fuera si el acceso se limita a 'origin'."""
    if not origin:
        return []
    try:
        net = ipaddress.ip_network(origin, strict=False)
    except ValueError:
        return []
    out = []
    for p in _remote_peers(ports):
        try:
            if ipaddress.ip_address(p) not in net:
                out.append(p)
        except ValueError:
            continue
    return out


def activar(ctx: Context, v: dict) -> bool:
    keep = _remote_ports() if v.get("mantener", True) else []
    origin = (v.get("origen") or "").strip()
    outside = _locks_out(origin, {p for p, _ in keep})
    if outside:
        ctx.out.error(f"Hay sesiones remotas abiertas desde {', '.join(sorted(outside))}, fuera de {origin}: "
                      "activar así las dejaría fuera. Incluye esas direcciones en el origen.")
        return False
    if not keep and _remote_ports():
        ctx.out.warn("No se deja abierto el acceso remoto: si estás conectado por SSH o RDP, perderás el acceso.")
    for port, what in keep:
        ctx.out.info(f"Dejando abierto {port}/tcp ({what}) antes de activar.")
        if not permitir(ctx, {"puerto": port, "protocolo": "tcp", "origen": origin}):
            ctx.out.error("No se pudo dejar abierto el acceso remoto; no se activa el firewall.")
            return False
    if origin and keep:
        ctx.out.warn(f"Las reglas que ya existieran para esos puertos siguen vigentes (en firewalld, el servicio "
                     f"«ssh» de la zona): revisa «Reglas» si el acceso debe quedar solo desde {origin}.")
    if backend() == "ufw":
        ok = apply(ctx, "firewall_activar", "ufw", ["ufw", "--force", "enable"])
    else:
        ok = apply(ctx, "firewall_activar", "firewalld", ["systemctl", "enable", "--now", "firewalld"])
    if ok:
        ctx.out.ok("Firewall activado. Todo lo que no esté permitido queda bloqueado desde la red.")
    return ok


def desactivar(ctx: Context, v: dict) -> bool:
    if backend() == "ufw":
        ok = apply(ctx, "firewall_desactivar", "ufw", ["ufw", "disable"])
    else:
        ok = apply(ctx, "firewall_desactivar", "firewalld", ["systemctl", "disable", "--now", "firewalld"])
    if ok:
        ctx.out.warn("Firewall desactivado: todos los puertos en escucha quedan accesibles desde la red.")
    return ok


def _activate_confirm(v: dict) -> str:
    keep = _remote_ports() if v.get("mantener", True) else []
    kept = ", ".join(f"{p} ({w})" for p, w in keep) or "ninguno"
    src = f" desde {v['origen']}" if v.get("origen") else ""
    return (f"Se activará el firewall. Se dejarán abiertos{src}: {kept}. Todo lo demás que no tenga una regla "
            "quedará bloqueado desde la red. ¿Continuar?")


class Firewall(Module):
    id = "firewall"
    name = "Firewall"
    category = "Sistemas"
    summary = "Estado y reglas del firewall (ufw o firewalld)"
    help = """\
# Firewall

Controla qué puertos de este equipo son accesibles **desde otros equipos**. Usa la herramienta
de firewall propia de la distribución: **ufw** en Debian/Ubuntu/Kali y **firewalld** en RHEL/SUSE.

- **Estado**: si está activo y qué permite.
- **Permitir un puerto**: abre un puerto, para todos o solo desde una IP/red concreta
  (recomendado: p. ej. el RDP solo desde la red de administración).
- **Quitar una regla**: en ufw, por su número de la lista.
- **Activar**: antes de activarlo **deja abiertos los puertos de SSH y escritorio remoto** que use este
  equipo (los lee de sshd y xrdp: no supone el 22 ni el 3389), para que no te quedes fuera. Puedes
  limitar ese acceso a un origen; si hay sesiones remotas abiertas desde fuera de ese origen, no se
  activa.
- **Desactivar**: deja todo accesible; úsalo solo para pruebas.

Si no hay ninguna herramienta de firewall instalada, el catálogo ofrece instalar la recomendada.
"""

    def detect(self) -> Status:
        if backend():
            return Status(AVAILABLE)
        fam = system.os_family()
        pkg = {"debian": "ufw", "rhel": "firewalld", "suse": "firewalld", "arch": "ufw"}.get(fam)
        if pkg and packages.manager().name != "ninguno":
            return Status(INSTALLABLE, packages=[pkg], reason=f"Falta una herramienta de firewall ({pkg})")
        return Status(UNAVAILABLE, reason="No hay ufw ni firewalld")

    def actions(self):
        src = Param("origen", "Solo desde (IP o red, opcional)", required=False,
                    help="Vacío = desde cualquier sitio. Ej.: 192.168.0.0/24")
        return [
            Action("estado", "Estado", estado),
            Action("reglas", "Ver reglas", listar_reglas),
            Action("permitir", "Permitir un puerto", permitir, changes=True, params=[
                Param("puerto", "Puerto o rango", help="Ej.: 443, 3389, 8000:8100"),
                Param("protocolo", "Protocolo", "choice", "tcp", choices=[("tcp", "TCP"), ("udp", "UDP")]), src]),
            Action("quitar", "Quitar una regla", quitar, changes=True, params=[
                Param("regla", "Número de regla (ufw) o puerto/protocolo (firewalld)",
                      help="Míralo antes en 'Ver reglas'."),
                Param("si_acceso_remoto", "Sí, quitar el acceso remoto (SSH/RDP)", "bool", False, required=False,
                      advanced=True, help="Puedes perder la conexión con este equipo.")],
                confirm="Se eliminará la regla {regla}. ¿Continuar?"),
            Action("activar", "Activar firewall", activar, changes=True, params=[
                Param("mantener", "Dejar abiertos SSH y escritorio remoto", "bool", True, required=False), src],
                confirm=_activate_confirm),
            Action("desactivar", "Desactivar firewall", desactivar, changes=True,
                   confirm="Se desactivará el firewall y todos los puertos quedarán accesibles desde la red. ¿Continuar?"),
        ]
