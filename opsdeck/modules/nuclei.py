"""Vulnerabilidades con nuclei: plantillas de la comunidad sobre webs y servicios."""

from __future__ import annotations

import json
from collections import Counter

from ..core import audit, feeds, nmapxml, results, scope
from ..core.catalog import Action, Context, Module, Param, cmd
from ..core.ops import stream
from .escaneo import escaneos

SEVERITIES = [("critical,high", "Crítica y alta"), ("critical,high,medium", "Crítica, alta y media"),
              ("critical,high,medium,low", "Todas salvo informativas"), ("info,low,medium,high,critical", "Todas")]


def actualizar(ctx: Context, v: dict) -> bool:
    rc, _ = stream(ctx, ["nuclei", "-update-templates", "-nc"], accion="nuclei_actualizar", objetivo="plantillas", keep=30)
    return rc == 0


def _targets_from_scan() -> list[str]:
    scans = escaneos()
    if not scans:
        return []
    out = []
    for h in nmapxml.parse(scans[0]).up():
        for p in h.open_ports():
            if p.is_web:
                out.append(f"{'https' if p.is_tls else 'http'}://{h.ip}:{p.port}")
            else:
                out.append(f"{h.ip}:{p.port}")
    return out


def analizar(ctx: Context, v: dict) -> bool:
    target = (v.get("objetivo") or "").strip()
    if target and not scope.gate(ctx, target, v, "nuclei"):
        return False
    targets = target.split() if target else _targets_from_scan()
    if not targets:
        ctx.out.error("Indica un objetivo o haz antes un 'Escaneo de red' (se usarán sus servicios).")
        return False
    feeds.warn_if_stale(ctx)
    d = results.new_dir("nuclei", target.replace("/", "_").replace(":", "_")[:40] or "ultimo_escaneo")
    tfile = d / "objetivos.txt"
    results.write(tfile, "\n".join(targets) + "\n")
    out = d / "hallazgos.jsonl"
    ctx.out.info(f"Analizando {len(targets)} objetivos (severidad: {v['severidad']}); s = detener...")
    rc, _ = stream(ctx, ["nuclei", "-l", str(tfile), "-severity", v["severidad"], "-jsonl", "-o", str(out),
                         "-nc", "-silent", "-rate-limit", "100"],
                   accion="nuclei_analizar", objetivo=target or "ultimo_escaneo", detalle=v["severidad"], keep=80)
    findings = []
    if out.exists():
        for line in out.read_text(errors="replace").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not findings:
        ctx.out.ok("nuclei no ha encontrado nada con esa severidad.")
        return rc == 0
    sev = Counter(f.get("info", {}).get("severity", "?") for f in findings)
    ctx.out.title("Hallazgos por severidad: " + "  ".join(f"{k}={sev[k]}" for k in
                                                         ("critical", "high", "medium", "low", "info") if sev.get(k)))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = [[f.get("info", {}).get("severity", "?"), f.get("matched-at", f.get("host", "?"))[:50],
             f.get("info", {}).get("name", f.get("template-id", "?"))[:60]]
            for f in sorted(findings, key=lambda f: order.get(f.get("info", {}).get("severity"), 9))]
    ctx.out.table(["Severidad", "Dónde", "Qué"], rows[:80])
    audit.record("nuclei_resultado", target or "ultimo_escaneo", "OK", " ".join(f"{k}={n}" for k, n in sev.items()))
    ctx.out.info(f"Detalle (referencias, cómo reproducirlo) en {out}")
    from ..core import recomendacion
    recomendacion.render(ctx, recomendacion.from_nuclei(findings))
    return True


class Nuclei(Module):
    full = True
    id = "nuclei"
    name = "Vulnerabilidades (nuclei)"
    category = "Ciberseguridad"
    summary = "Detecta vulnerabilidades conocidas y configuraciones inseguras con plantillas"
    requires = [cmd("nuclei", debian="nuclei", arch="nuclei", label="nuclei")]
    families = ("debian", "arch")
    help = """\
# Vulnerabilidades (nuclei)

> Solo contra sistemas propios o con autorización por escrito.

nuclei comprueba miles de **vulnerabilidades conocidas** (CVE), paneles expuestos, configuraciones
por defecto y fallos comunes, usando plantillas que mantiene la comunidad.

1. **Actualizar plantillas** la primera vez y de vez en cuando.
2. **Analizar**: sobre una URL/equipo o, si lo dejas vacío, sobre **todos los servicios del último
   escaneo de red**. Empieza por severidad crítica y alta.

A diferencia del "CVSS" del escaneo de nmap (que solo mira el número de versión), nuclei
**comprueba** el fallo, así que sus hallazgos son mucho más fiables.
"""

    def actions(self):
        return [
            Action("actualizar", "Actualizar plantillas", actualizar),
            Action("analizar", "Analizar", analizar, params=[
                Param("objetivo", "Objetivo (vacío = servicios del último escaneo)", required=False),
                Param("severidad", "Severidad", "choice", "critical,high", choices=SEVERITIES),
                scope.ok_param()],
                confirm=lambda v: f"nuclei enviará pruebas activas a {v.get('objetivo') or 'los servicios del último escaneo'}. "
                                  "¿Tienes autorización?"),
        ]
