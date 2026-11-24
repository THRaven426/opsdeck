"""Registro de auditoría: una línea JSON por cambio (quién, qué, sobre qué, resultado).
Nunca se registran contraseñas. Rota por tamaño y copia cada línea al syslog/journal."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import syslog
import tarfile
import time
from pathlib import Path

from .. import NAME
from . import paths, system
from .config import settings


def _rotate(log: Path, max_kb: int, keep: int) -> None:
    if not log.exists() or log.stat().st_size < max_kb * 1024:
        return
    oldest = log.with_name(f"{log.name}.{keep}.gz")
    oldest.unlink(missing_ok=True)
    for i in range(keep - 1, 0, -1):
        src = log.with_name(f"{log.name}.{i}.gz")
        if src.exists():
            src.rename(log.with_name(f"{log.name}.{i + 1}.gz"))
    rotated = log.with_name(f"{log.name}.1.gz")
    with open(log, "rb") as f_in, open(os.open(rotated, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640), "wb") as raw, \
            gzip.GzipFile(fileobj=raw, mode="wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.chmod(rotated, 0o640)
    log.write_text("")


def record(action: str, target: str, result: str, detail: str = "") -> None:
    cfg = settings()
    entry = {
        "fecha": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": system.hostname(),
        "operador": system.operator(),
        "accion": action,
        "objetivo": target,
        "resultado": result,
    }
    if detail:
        entry["detalle"] = detail
    line = json.dumps(entry, ensure_ascii=False)
    if cfg.getboolean("auditoria", "fichero"):
        try:
            paths.ensure_private_dir(paths.LOG_DIR, 0o750)
            _rotate(paths.AUDIT_LOG, cfg.getint("auditoria", "max_kb"), cfg.getint("auditoria", "conservar"))
            with open(paths.AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            os.chmod(paths.AUDIT_LOG, 0o640)
        except OSError:
            pass
    if cfg.getboolean("auditoria", "syslog"):
        try:
            syslog.openlog(NAME, 0, syslog.LOG_AUTHPRIV)
            syslog.syslog(syslog.LOG_NOTICE, line)
        except Exception:
            pass


def read(limit: int = 50, text: str = "") -> list[dict]:
    if not paths.AUDIT_LOG.exists():
        return []
    rows = []
    for line in paths.AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        if text and text.lower() not in line.lower():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-limit:]


def snapshot_accounts() -> str:
    """Copia de passwd/shadow/group/gshadow/sudoers antes de un cambio (solo root la lee).
    Devuelve la ruta, '' si las copias están desactivadas o 'ERROR' si no se pudo hacer."""
    cfg = settings()
    if not cfg.getboolean("copias", "cuentas"):
        return ""
    try:
        paths.ensure_private_dir(paths.DATA_DIR, 0o750)
        paths.ensure_private_dir(paths.BACKUP_DIR)
        dest = paths.BACKUP_DIR / f"cuentas_{time.strftime('%Y%m%d_%H%M%S')}_{time.time_ns() % 10**9:09d}.tar.gz"
        with tarfile.open(dest, "w:gz") as tar:
            for p in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d"):
                if Path(p).exists():
                    tar.add(p)
        os.chmod(dest, 0o600)
        keep = cfg.getint("copias", "conservar")
        olds = sorted(paths.BACKUP_DIR.glob("cuentas_*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)
        for old in olds[keep:]:
            old.unlink(missing_ok=True)
        return str(dest)
    except OSError:
        return "ERROR"
