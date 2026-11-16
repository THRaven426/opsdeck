"""Rootkits: rkhunter (y chkrootkit si está instalado)."""

from __future__ import annotations

from ..core import audit, results, system
from ..core.catalog import Action, Context, Module, cmd
from ..core.ops import stream


def preparar(ctx: Context, v: dict) -> bool:
    stream(ctx, ["rkhunter", "--update", "--nocolors"], accion="rkhunter_actualizar", objetivo="datos", keep=20)
    rc, _ = stream(ctx, ["rkhunter", "--propupd", "--nocolors"], accion="rkhunter_linea_base", objetivo="propiedades")
    if rc == 0:
        ctx.out.ok("Línea base guardada: a partir de ahora se avisará si cambian los binarios del sistema.")
    return rc == 0


def analizar(ctx: Context, v: dict) -> bool:
    d = results.new_dir("rootkits", "rkhunter")
    ctx.out.info("Analizando con rkhunter (unos minutos)...")
    rc, out = stream(ctx, ["rkhunter", "--check", "--sk", "--rwo", "--nocolors"], accion="rkhunter_analizar",
                     objetivo=system.hostname(), save_to=d / "rkhunter.txt", show=False)
    warnings = [l for l in out.splitlines() if l.strip()]
    if warnings:
        ctx.out.warn(f"{len(warnings)} avisos:")
        for l in warnings[:60]:
            ctx.out.line("  " + l)
        ctx.out.info("Tras actualizar paquetes, rkhunter avisa de binarios cambiados: si es por una actualización "
                     "legítima, usa 'Preparar / actualizar línea base'.")
    else:
        ctx.out.ok("rkhunter no encuentra nada sospechoso.")
    if system.has_cmd("chkrootkit"):
        ctx.out.title("Segunda opinión: chkrootkit")
        _, out2 = stream(ctx, ["chkrootkit", "-q"], accion="chkrootkit_analizar", objetivo=system.hostname(),
                         save_to=d / "chkrootkit.txt", show=False)
        found = [l for l in out2.splitlines() if l.strip()]
        for l in found[:30]:
            ctx.out.line("  " + l)
        if not found:
            ctx.out.ok("chkrootkit no encuentra nada.")
    audit.record("rootkits_resultado", system.hostname(), "AVISOS" if warnings else "LIMPIO", f"{len(warnings)} avisos")
    return True


class Rootkits(Module):
    full = True
    id = "rootkits"
    name = "Rootkits (rkhunter)"
    category = "Blue team"
    summary = "Busca rootkits, puertas traseras y binarios del sistema alterados"
    requires = [cmd("rkhunter", debian="rkhunter", rhel="rkhunter", suse="rkhunter", arch="rkhunter")]
    help = """\
# Rootkits (rkhunter)

Un **rootkit** es malware que se esconde modificando el sistema. rkhunter compara los binarios
del sistema con una **línea base** y busca rastros de rootkits conocidos.

1. **Preparar / actualizar línea base**: hazlo con el equipo en buen estado (y después de cada
   actualización del sistema, para que no avise de los cambios legítimos).
2. **Analizar**: muestra solo los avisos. Si `chkrootkit` está instalado se usa también como segunda opinión.

Tiene falsos positivos: un aviso es un punto de partida, no una prueba.
"""

    def actions(self):
        return [
            Action("preparar", "Preparar / actualizar línea base", preparar, changes=True),
            Action("analizar", "Analizar", analizar),
        ]
