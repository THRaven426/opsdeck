"""Fuentes de datos: estado y actualización de las bases de las que depende la detección
(plantillas de nuclei, exploit-db y listas de paquetes del sistema)."""

from __future__ import annotations

from ..core import feeds, system
from ..core.catalog import Action, Context, Module
from ..core.ops import stream


def estado(ctx: Context, v: dict) -> bool:
    fs = feeds.status()
    ctx.out.title("Fuentes de datos")
    rows = []
    for f in fs:
        if not f.presente:
            edad = "—"
        elif f.edad_dias is None:
            edad = "?"
        else:
            edad = f"{f.edad_dias} días" + ("  ⚠ vieja" if f.vieja else "")
        rows.append([f.nombre, "sí" if f.presente else "no", edad, f.detalle])
    ctx.out.table(["Fuente", "Disponible", "Antigüedad", "Detalle"], rows)
    if feeds.stale(fs):
        ctx.out.warn(f"Hay fuentes con más de {feeds.UMBRAL_DIAS} días. Usa «Actualizar fuentes» antes de analizar.")
    else:
        ctx.out.ok("Las fuentes disponibles están al día.")
    ctx.out.info("La detección es tan reciente como estas fuentes: no dependen de la fecha del modelo.")
    return True


def actualizar(ctx: Context, v: dict) -> bool:
    if not system.is_root():
        ctx.out.error("Actualizar las fuentes necesita root. Abre la herramienta escribiendo solo: opsdeck")
        return False
    hecho = False
    if system.has_cmd("nuclei"):
        ctx.out.info("Actualizando plantillas de nuclei...")
        stream(ctx, ["nuclei", "-update-templates", "-nc"], accion="feeds_nuclei", objetivo="plantillas", keep=20)
        hecho = True
    if system.has_cmd("searchsploit"):
        ctx.out.info("Actualizando la base de exploit-db...")
        stream(ctx, ["searchsploit", "-u"], accion="feeds_exploitdb", objetivo="exploit-db", keep=20)
        hecho = True
    if system.has_cmd("apt-get"):
        ctx.out.info("Actualizando las listas de paquetes (apt-get update)...")
        stream(ctx, ["apt-get", "update"], accion="feeds_apt", objetivo="listas apt", keep=20)
        hecho = True
    if not hecho:
        ctx.out.warn("No hay ninguna fuente que actualizar en este equipo (ni nuclei, ni searchsploit, ni apt).")
        return False
    ctx.out.ok("Fuentes actualizadas.")
    return estado(ctx, v)


class Fuentes(Module):
    id = "fuentes"
    name = "Fuentes de datos"
    category = "Ciberseguridad"
    summary = "Estado y actualización de las bases de detección (nuclei, exploit-db, parches)"
    requires = []
    help = """\
# Fuentes de datos

La detección de opsdeck **no depende de la fecha del modelo**, sino de fuentes que se actualizan a
diario. Aquí ves cuándo se actualizaron por última vez y puedes ponerlas al día:

- **Plantillas de nuclei**: las reglas que comprueban vulnerabilidades conocidas (CVE), paneles
  expuestos y configuraciones inseguras. Para un fallo reciente y sonado suelen aparecer en días.
- **Base de exploit-db (searchsploit)**: para saber si una vulnerabilidad tiene exploit público y
  así priorizarla.
- **Listas de paquetes (apt)**: de donde salen los parches de seguridad que se pueden aplicar.

> Analizar con fuentes viejas puede dejar fuera lo más reciente. Antes de una auditoría, actualiza.
"""

    def actions(self):
        return [
            Action("estado", "Estado de las fuentes", estado),
            Action("actualizar", "Actualizar fuentes", actualizar, changes=True,
                   help="Actualiza plantillas de nuclei, exploit-db y listas de paquetes (lo que esté instalado).",
                   confirm="Se descargarán las últimas plantillas, exploits y listas de paquetes. ¿Continuar?"),
        ]
