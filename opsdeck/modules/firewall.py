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
            ok = apply(ctx, "firewall_permitir", target, ["firewall-cmd", "--permanent", f"--add-rich-rule={rule}"])
        else:
            ok = apply(ctx, "firewall_permitir", target,
                       ["firewall-cmd", "--permanent", f"--add-port={port.replace(':', '-')}/{proto}"])
        ok = ok and apply(ctx, "firewall_recargar", "firewalld", ["firewall-cmd", "--reload"], quiet=True)
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
        ok = apply(ctx, "firewall_quitar", match[1], ["ufw", "--force", "delete", num])
    else:
        spec = v["regla"].strip()
        if not re.match(r"^\d{1,5}(-\d{1,5})?/(tcp|udp)$", spec):
            ctx.out.error("Indica el puerto como en la lista: 8080/tcp")
            return False
        ok = apply(ctx, "firewall_quitar", spec, ["firewall-cmd", "--permanent", f"--remove-port={spec}"]) and \
            apply(ctx, "firewall_recargar", "firewalld", ["firewall-cmd", "--reload"], quiet=True)
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


def _remote_ports() -> list[tuple[str, str]]:
    ports = []
    listen = system.run(["ss", "-ltnH"], c_locale=True).out if system.has_cmd("ss") else ""
    local = {l.split()[3].rpartition(":")[2] for l in listen.splitlines() if len(l.split()) > 3}
    if "22" in local or system.has_cmd("sshd"):
        ports.append(("22", "SSH"))
    if "3389" in local or system.has_cmd("xrdp"):
        ports.append(("3389", "escritorio remoto"))
    return ports


def activar(ctx: Context, v: dict) -> bool:
    keep = _remote_ports() if v.get("mantener", True) else []
    for port, what in keep:
        ctx.out.info(f"Dejando abierto {port}/tcp ({what}) antes de activar.")
        if not permitir(ctx, {"puerto": port, "protocolo": "tcp", "origen": v.get("origen", "")}):
            ctx.out.error("No se pudo dejar abierto el acceso remoto; no se activa el firewall.")
            return False
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
    src = f" solo desde {v['origen']}" if v.get("origen") else ""
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
- **Activar**: antes de activarlo **deja abiertos SSH (22) y escritorio remoto (3389)** si están en uso,
  para que no te quedes fuera. Puedes limitar ese acceso a un origen.
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
                      help="Míralo antes en 'Ver reglas'.")],
                confirm="Se eliminará la regla {regla}. ¿Continuar?"),
            Action("activar", "Activar firewall", activar, changes=True, params=[
                Param("mantener", "Dejar abiertos SSH y escritorio remoto", "bool", True, required=False), src],
                confirm=_activate_confirm),
            Action("desactivar", "Desactivar firewall", desactivar, changes=True,
                   confirm="Se desactivará el firewall y todos los puertos quedarán accesibles desde la red. ¿Continuar?"),
        ]
