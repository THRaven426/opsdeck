"""Integridad de ficheros con AIDE: crear la base de referencia, comprobar cambios y aceptarlos."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..core import audit, results, system
from ..core.catalog import Action, Context, Module, cmd
from ..core.ops import stream

CONF_CANDIDATES = ("/etc/aide/aide.conf", "/etc/aide.conf")


def conf() -> str:
    return next((c for c in CONF_CANDIDATES if Path(c).exists()), CONF_CANDIDATES[0])


def db_paths() -> tuple[Path, Path]:
    """(base en uso, base nueva) según la configuración de AIDE."""
    text = ""
    try:
        text = Path(conf()).read_text(errors="replace")
    except OSError:
        pass
    cur = re.search(r"^database(?:_in)?\s*=\s*file:(\S+)", text, re.M)
    new = re.search(r"^database_out\s*=\s*file:(\S+)", text, re.M)
    dbdir = "/var/lib/aide"
    return (Path(cur.group(1).replace("@@{DBDIR}", dbdir)) if cur else Path(dbdir, "aide.db"),
            Path(new.group(1).replace("@@{DBDIR}", dbdir)) if new else Path(dbdir, "aide.db.new"))


def _promote(ctx, new: Path, cur: Path) -> bool:
    if not new.exists():
        ctx.out.error(f"AIDE no generó {new}")
        return False
    cur.parent.mkdir(parents=True, exist_ok=True)
    new.chmod(0o600)
    shutil.move(str(new), str(cur))
    return True


def crear(ctx: Context, v: dict) -> bool:
    cur, new = db_paths()
    ctx.out.info("Calculando la huella de los ficheros del sistema (puede tardar 10-30 minutos; s = detener)...")
    rc, _ = stream(ctx, ["aide", "--config", conf(), "--init"], accion="aide_crear_base", objetivo=str(cur), keep=30)
    if rc not in (0,) or not _promote(ctx, new, cur):
        return False
    ctx.out.ok(f"Base de referencia creada: {cur}. Guárdala también fuera del equipo si es posible.")
    return True


def comprobar(ctx: Context, v: dict) -> bool:
    cur, _ = db_paths()
    if not cur.exists():
        ctx.out.error("Todavía no hay base de referencia: usa 'Crear base de referencia'.")
        return False
    d = results.new_dir("integridad", "comprobacion")
    ctx.out.info("Comparando el sistema con la base de referencia...")
    rc, out = stream(ctx, ["aide", "--config", conf(), "--check"], accion="aide_comprobar",
                     objetivo=system.hostname(), save_to=d / "aide.txt", keep=80)
    # AIDE: 0 sin cambios; bits 1/2/4 = añadidos/eliminados/cambiados
    if rc == 0:
        ctx.out.ok("Sin cambios desde la base de referencia.")
    elif 0 < rc < 8:
        parts = [txt for bit, txt in ((1, "ficheros nuevos"), (2, "ficheros eliminados"), (4, "ficheros cambiados")) if rc & bit]
        ctx.out.warn("Hay " + ", ".join(parts) + ". Revisa la lista: si son cambios esperados (actualizaciones), "
                     "usa 'Aceptar los cambios'.")
    else:
        ctx.out.error(f"AIDE terminó con error ({rc}).")
    audit.record("aide_resultado", system.hostname(), "SIN_CAMBIOS" if rc == 0 else f"CAMBIOS_{rc}", str(d))
    return rc < 8


def aceptar(ctx: Context, v: dict) -> bool:
    cur, new = db_paths()
    rc, _ = stream(ctx, ["aide", "--config", conf(), "--update"], accion="aide_aceptar_cambios", objetivo=str(cur), keep=30)
    if rc >= 8 or not _promote(ctx, new, cur):
        return False
    ctx.out.ok("Cambios aceptados: la base de referencia se ha actualizado.")
    return True


class Integridad(Module):
    full = True
    id = "integridad"
    name = "Integridad (AIDE)"
    category = "Blue team"
    summary = "Detecta cambios en ficheros del sistema respecto a una referencia"
    requires = [cmd("aide", debian="aide", rhel="aide", suse="aide", arch="aide")]
    help = """\
# Integridad de ficheros (AIDE)

AIDE guarda la "huella" de los ficheros importantes del sistema y después te dice **qué ha
cambiado, qué se ha añadido y qué se ha borrado**. Sirve para detectar binarios sustituidos,
configuraciones alteradas o puertas traseras.

1. **Crear base de referencia** con el equipo en buen estado (tarda).
2. **Comprobar** periódicamente.
3. Tras cambios **legítimos** (actualizaciones, cambios de configuración tuyos): **Aceptar los cambios**.

Consejo: guarda una copia de la base fuera del equipo; un atacante con root podría modificarla.
"""

    def actions(self):
        return [
            Action("crear", "Crear base de referencia", crear, changes=True,
                   confirm="Se creará (o sustituirá) la base de referencia de AIDE. Tarda varios minutos. ¿Continuar?"),
            Action("comprobar", "Comprobar cambios", comprobar),
            Action("aceptar", "Aceptar los cambios", aceptar, changes=True,
                   confirm="Los cambios actuales pasarán a ser la nueva referencia. Hazlo solo si son legítimos. ¿Continuar?"),
        ]
