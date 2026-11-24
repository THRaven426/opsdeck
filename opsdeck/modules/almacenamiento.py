"""Almacenamiento: uso de discos, qué ocupa más espacio y limpieza segura."""

from __future__ import annotations

import re
from pathlib import Path

from ..core import system, tooling
from ..core.catalog import Action, Context, Module, Param
from ..core.ops import apply

PSEUDO = ("tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs")


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def discos(ctx: Context, v: dict) -> bool:
    args = ["df", "-hT"] + [x for t in PSEUDO for x in ("-x", t)]
    r = system.run(args, c_locale=True)
    rows = [l.split() for l in r.out.splitlines()[1:] if l.strip()]
    ctx.out.table(["Dispositivo", "Tipo", "Tamaño", "Usado", "Libre", "Uso", "Montado en"],
                  [x[:7] for x in rows if len(x) >= 7])
    r = system.run(["df", "-i"] + [x for t in PSEUDO for x in ("-x", t)], c_locale=True)
    full = False
    for x in (l.split() for l in r.out.splitlines()[1:]):
        if len(x) >= 6 and x[4].rstrip("%").isdigit() and int(x[4].rstrip("%")) >= 90:
            ctx.out.warn(f"{x[5]}: {x[4]} de inodos usados (demasiados ficheros pequeños)")
            full = True
    for x in rows:
        if len(x) >= 7 and x[5].rstrip("%").isdigit() and int(x[5].rstrip("%")) >= 90:
            ctx.out.warn(f"{x[6]} está al {x[5]}: usa 'Qué ocupa más' sobre esa ruta.")
            full = True
    if not full:
        ctx.out.ok("Ningún disco por encima del 90 %.")
    if system.has_cmd("lsblk"):
        r = system.run(["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT", "-e", "7"], c_locale=True)
        ctx.out.title("Discos y particiones")
        for line in r.out.splitlines():
            ctx.out.line(line)
    return True


def _path(ctx, p: str) -> Path | None:
    path = Path(p or "/").resolve()
    if not path.is_dir():
        ctx.out.error(f"No existe la carpeta {path}")
        return None
    return path


def ocupa(ctx: Context, v: dict) -> bool:
    path = _path(ctx, v.get("ruta", "/"))
    if not path:
        return False
    ctx.out.info(f"Calculando el tamaño de cada carpeta dentro de {path} (puede tardar)...")
    r = system.run(["du", "-x", "-b", "--max-depth=1", str(path)], c_locale=True, timeout=900)
    rows = []
    for line in r.out.splitlines():
        size, _, name = line.partition("\t")
        if size.isdigit() and name != str(path):
            rows.append((int(size), name))
    total = next((int(l.split("\t")[0]) for l in r.out.splitlines() if l.endswith("\t" + str(path))), 0)
    rows.sort(reverse=True)
    ctx.out.title(f"{path}: {_human(total)} en total")
    ctx.out.table(["Tamaño", "%", "Carpeta"], [[_human(s), f"{s * 100 / total:.0f}" if total else "-", n]
                                              for s, n in rows[:20]])
    ctx.out.info("Para bajar un nivel, repite con la carpeta que más ocupe.")
    return True


def grandes(ctx: Context, v: dict) -> bool:
    path = _path(ctx, v.get("ruta", "/"))
    if not path:
        return False
    try:
        mb = int(v.get("minimo") or 500)
    except ValueError:
        mb = 500
    ctx.out.info(f"Buscando ficheros de más de {mb} MB en {path}...")
    r = system.run(["find", str(path), "-xdev", "-type", "f", "-size", f"+{mb}M", "-printf", "%s\t%TY-%Tm-%Td\t%p\n"],
                   c_locale=True, timeout=900)
    rows = []
    for line in r.out.splitlines():
        f = line.split("\t", 2)
        if len(f) == 3 and f[0].isdigit():
            rows.append((int(f[0]), f[1], f[2]))
    rows.sort(reverse=True)
    if not rows:
        ctx.out.ok("No hay ficheros tan grandes.")
        return True
    ctx.out.table(["Tamaño", "Modificado", "Fichero"], [[_human(s), d, p] for s, d, p in rows[:30]])
    return True


def _du(path: str) -> int:
    r = system.run(["du", "-sb", path], c_locale=True)
    try:
        return int(r.out.split()[0])
    except (IndexError, ValueError):
        return 0


def _journal_size() -> int:
    r = system.run(["journalctl", "--disk-usage"], c_locale=True) if system.has_cmd("journalctl") else None
    if not r or not r.ok:
        return 0
    m = re.search(r"([\d.]+)([KMGT])?B?", r.out.split("take up", 1)[-1])
    if not m:
        return 0
    return int(float(m.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}.get(m.group(2) or "", 1))


def liberable(ctx: Context, v: dict) -> bool:
    rows = []
    if Path("/var/cache/apt/archives").is_dir():
        rows.append(["Paquetes descargados (caché de apt)", _human(_du("/var/cache/apt/archives"))])
    js = _journal_size()
    if js:
        rows.append(["Registros del sistema (journal)", _human(js)])
    if Path("/var/lib/opsdeck/backups").is_dir():
        rows.append(["Copias de opsdeck (no se borran desde aquí)", _human(_du("/var/lib/opsdeck/backups"))])
    trash = sum(_du(str(p)) for p in Path("/home").glob("*/.local/share/Trash") if p.is_dir())
    if trash:
        rows.append(["Papeleras de los usuarios", _human(trash)])
    ctx.out.table(["Qué", "Ocupa"], rows)
    ctx.out.info("Usa 'Liberar espacio' para limpiar la caché de paquetes y los registros antiguos.")
    return True


def limpiar(ctx: Context, v: dict) -> bool:
    done = False
    if v.get("cache") and system.has_cmd("apt-get"):
        before = _du("/var/cache/apt/archives")
        if apply(ctx, "limpiar_cache_apt", "/var/cache/apt/archives", ["apt-get", "clean"]):
            ctx.out.ok(f"Caché de paquetes: liberados {_human(before - _du('/var/cache/apt/archives'))}")
            done = True
    if v.get("journal") and system.has_cmd("journalctl"):
        days = str(tooling.int_in(v.get("dias"), 30, 1, 3650))
        before = _journal_size()
        if apply(ctx, "limpiar_journal", f"{days}d", ["journalctl", f"--vacuum-time={days}d"], quiet=True):
            ctx.out.ok(f"Registros de más de {days} días eliminados: liberados {_human(max(0, before - _journal_size()))}")
            done = True
    if not done:
        ctx.out.info("No se ha marcado nada para limpiar.")
    return True


class Almacenamiento(Module):
    id = "almacenamiento"
    name = "Almacenamiento"
    category = "Sistemas"
    summary = "Uso de discos, qué ocupa más espacio y limpieza segura"
    help = """\
# Almacenamiento

- **Uso de discos**: espacio de cada disco y partición; avisa a partir del 90 % (también de *inodos*,
  que se agotan cuando hay millones de ficheros pequeños aunque quede espacio).
- **Qué ocupa más**: tamaño de cada carpeta dentro de una ruta. Repite bajando de nivel hasta dar
  con el culpable. No cruza a otros discos.
- **Ficheros grandes**: los ficheros de más de N MB.
- **Qué se puede liberar** y **Liberar espacio**: solo limpia cosas seguras de borrar:
  la caché de paquetes descargados (se vuelven a bajar si hacen falta) y los registros del sistema
  más antiguos que los días que elijas. Nunca borra datos de usuarios.
"""

    def actions(self):
        ruta = Param("ruta", "Carpeta", default="/", help="Ej.: /, /var, /home")
        return [
            Action("discos", "Uso de discos", discos),
            Action("ocupa", "Qué ocupa más", ocupa, params=[ruta]),
            Action("grandes", "Ficheros grandes", grandes, params=[
                ruta, Param("minimo", "Tamaño mínimo (MB)", "int", 500, required=False)]),
            Action("liberable", "Qué se puede liberar", liberable),
            Action("limpiar", "Liberar espacio", limpiar, changes=True, params=[
                Param("cache", "Vaciar la caché de paquetes descargados", "bool", True, required=False),
                Param("journal", "Borrar registros del sistema antiguos", "bool", True, required=False),
                Param("dias", "Conservar registros de los últimos N días", "int", 30, required=False)],
                confirm="Se vaciará lo marcado (caché de paquetes y/o registros antiguos). ¿Continuar?"),
        ]
