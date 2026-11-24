"""Resultados guardados de escaneos, análisis e informes: /var/lib/opsdeck/resultados/<módulo>/.
Cada ejecución tiene su carpeta con fecha; solo root puede leerlas."""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from . import paths

ROOT = paths.DATA_DIR / "resultados"


def safe(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("_")[:60] or "sin_nombre"


def _keep() -> int:
    from .config import settings
    return settings().getint("resultados", "conservar_por_modulo", fallback=50)


def prune(module_id: str) -> int:
    """Borra los resultados más antiguos de un módulo por encima del límite configurado."""
    keep = _keep()
    if keep <= 0:
        return 0
    old = sessions(module_id, limit=10_000)[keep:]
    for d in old:
        shutil.rmtree(d, ignore_errors=True)
    return len(old)


def new_dir(module_id: str, label: str) -> Path:
    paths.ensure_private_dir(paths.DATA_DIR, 0o750)
    base = paths.ensure_private_dir(ROOT, 0o750)
    mod = paths.ensure_private_dir(base / module_id, 0o750)
    d = mod / f"{time.strftime('%Y%m%d_%H%M%S')}_{safe(label)}"
    n = 1
    while d.exists():                      # dos ejecuciones en el mismo segundo
        n += 1
        d = mod / f"{time.strftime('%Y%m%d_%H%M%S')}_{safe(label)}_{n}"
    d.mkdir(mode=0o750)
    prune(module_id)
    return d


def all_sessions(limit: int = 200) -> list[tuple[str, Path]]:
    if not ROOT.is_dir():
        return []
    out = [(m.name, d) for m in ROOT.iterdir() if m.is_dir() for d in m.iterdir() if d.is_dir()]
    return sorted(out, key=lambda x: x[1].name, reverse=True)[:limit]


def sessions(module_id: str, limit: int = 30) -> list[Path]:
    d = ROOT / module_id
    if not d.is_dir():
        return []
    return sorted((p for p in d.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)[:limit]


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o640)
    return path


def csv_safe(row) -> list[str]:
    """Celdas de un CSV que se abrirá en una hoja de cálculo: un valor que empieza por = + - @ (un
    nombre de usuario, un GECOS, el CN de un certificado...) se trataría como fórmula."""
    out = []
    for v in row:
        s = str(v)
        formula = s[:1] in ("=", "+", "-", "@", "\t", "\r") and not re.fullmatch(r"-?\d+(\.\d+)?", s)
        out.append("'" + s if formula else s)
    return out
