"""Bastionado con Lynis: auditoría con índice de bastionado, avisos, sugerencias e historial."""

from __future__ import annotations

import re
from pathlib import Path

from ..core import audit, results, system
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream

GROUPS = [("", "Todas (recomendado)"), ("authentication", "Autenticación"), ("ssh", "SSH"),
          ("firewalls", "Firewall"), ("file_permissions", "Permisos de ficheros"), ("kernel", "Kernel"),
          ("networking", "Red"), ("logging", "Registros"), ("malware", "Malware"), ("webservers", "Servidores web")]


def parse_report(path: Path) -> dict:
    data: dict = {"warning": [], "suggestion": []}
    if not path.exists():
        return data
    for line in path.read_text(errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        if k in ("warning[]", "suggestion[]"):
            parts = v.split("|")
            data[k[:-2]].append({"id": parts[0], "texto": parts[1] if len(parts) > 1 else "",
                                 "detalle": parts[2] if len(parts) > 2 and parts[2] != "-" else ""})
        elif k in ("hardening_index", "lynis_tests_done", "lynis_version", "report_datetime_start"):
            data[k] = v
    return data


def auditar(ctx: Context, v: dict) -> bool:
    d = results.new_dir("bastionado", v.get("grupo") or "completa")
    report, log = d / "lynis-report.dat", d / "lynis.log"
    args = ["lynis", "audit", "system", "--quick", "--no-colors", "--report-file", str(report), "--log-file", str(log)]
    if v.get("grupo"):
        args += ["--tests-from-group", v["grupo"]]
    tests = (v.get("pruebas") or "").replace(" ", "")
    if tests:
        if not re.match(r"^[A-Z]{3,5}-\d{4}(,[A-Z]{3,5}-\d{4})*$", tests):
            ctx.out.error("IDs de prueba no válidos. Ej.: SSH-7408,AUTH-9286")
            return False
        args += ["--tests", tests.replace(",", " ")]
    if v.get("pentest"):
        args.append("--pentest")
    if not v.get("rapido", True):
        args.remove("--quick")
    perfil = (v.get("perfil") or "").strip()
    if perfil:
        if not Path(perfil).is_file():
            ctx.out.error(f"No existe el perfil {perfil}")
            return False
        args += ["--profile", perfil]
    ctx.out.info("Auditando el sistema con Lynis (unos minutos)...")
    rc, _ = stream(ctx, args, accion="lynis_auditoria", objetivo=system.hostname(), save_to=d / "salida.txt", keep=40)
    data = parse_report(report)
    if not data.get("hardening_index"):
        ctx.out.error("Lynis no generó informe. Revisa la salida.")
        return False
    idx = int(data["hardening_index"])
    ctx.out.title(f"Índice de bastionado: {idx}/100   ·   {data.get('lynis_tests_done', '?')} pruebas")
    ctx.out.line("  " + "█" * (idx // 5) + "░" * (20 - idx // 5))
    prev = [s for s in results.sessions("bastionado") if s != d and (s / "lynis-report.dat").exists()]
    if prev:
        old = parse_report(prev[0] / "lynis-report.dat").get("hardening_index")
        if old:
            delta = idx - int(old)
            ctx.out.info(f"Anterior ({prev[0].name[:8]}): {old} → {'+' if delta >= 0 else ''}{delta}")
    if data["warning"]:
        ctx.out.title(f"Avisos ({len(data['warning'])}) — atender primero")
        for w in data["warning"]:
            ctx.out.check(False, f"{w['texto']} [{w['id']}]" + (f" · {w['detalle']}" if w["detalle"] else ""))
    ctx.out.title(f"Sugerencias ({len(data['suggestion'])})")
    for s in data["suggestion"][:40]:
        ctx.out.line(f"  • {s['texto']} [{s['id']}]")
    if len(data["suggestion"]) > 40:
        ctx.out.info(f"... y {len(data['suggestion']) - 40} más en {d}")
    ctx.out.info(f"Para saber más de una prueba: lynis show details <ID>.  Informe: {report}")
    audit.record("lynis_indice", system.hostname(), "OK", f"indice={idx} avisos={len(data['warning'])}")
    return True


def historial(ctx: Context, v: dict) -> bool:
    rows = []
    for s in results.sessions("bastionado", 30):
        data = parse_report(s / "lynis-report.dat")
        if data.get("hardening_index"):
            rows.append([f"{s.name[:4]}-{s.name[4:6]}-{s.name[6:8]} {s.name[9:11]}:{s.name[11:13]}",
                         s.name[16:] or "completa", data["hardening_index"], str(len(data["warning"])),
                         str(len(data["suggestion"]))])
    if not rows:
        ctx.out.info("Aún no hay auditorías guardadas.")
        return True
    ctx.out.table(["Fecha", "Alcance", "Índice", "Avisos", "Sugerencias"], rows)
    return True


class Bastionado(Module):
    full = True
    id = "bastionado"
    name = "Bastionado (Lynis)"
    category = "Blue team"
    summary = "Auditoría profunda con índice de bastionado y su evolución"
    requires = [cmd("lynis", debian="lynis", rhel="lynis", suse="lynis", arch="lynis")]
    help = """\
# Bastionado (Lynis)

Lynis revisa **cientos de puntos** de configuración y da un **índice de bastionado** de 0 a 100.
Una instalación recién hecha suele rondar 55-65; un servidor bien configurado, 80 o más.

- **Auditar**: completa o solo un área (SSH, firewall, autenticación...). Muestra primero los
  **avisos** (lo importante) y después las **sugerencias**.
- **Historial**: el índice de cada auditoría, para ver si mejora tras aplicar cambios.

**Opciones avanzadas**: solo unas pruebas concretas por ID, modo sin privilegios (`--pentest`) y un
perfil propio (`.prf`) para adaptar Lynis a la política de la organización.

Flujo recomendado: auditar → corregir los avisos → volver a auditar y comparar.
Para una revisión rápida sin instalar nada usa *Revisión de seguridad*.
"""

    def actions(self):
        return [
            Action("auditar", "Auditar", auditar, params=[
                Param("grupo", "Alcance", "choice", "", choices=GROUPS, required=False),
                Param("pruebas", "Solo estas pruebas (IDs de Lynis)", required=False, advanced=True,
                      help="Ej.: SSH-7408,AUTH-9286 (lynis show tests para verlas)"),
                Param("pentest", "Modo sin privilegios (--pentest), como lo vería un usuario normal", "bool", False,
                      required=False, advanced=True),
                Param("rapido", "Sin pausas entre secciones (--quick)", "bool", True, required=False, advanced=True),
                Param("perfil", "Perfil de Lynis personalizado (.prf)", required=False, advanced=True,
                      help="Para ajustar o saltar pruebas según la política de tu organización")],
                   help="Ejecuta Lynis, guarda el informe y lo compara con la auditoría anterior."),
            Action("historial", "Historial del índice", historial),
        ]
