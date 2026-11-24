"""Lectura segura, como root, de ficheros que puede controlar otro usuario.

Sin seguir enlaces simbólicos en el último componente (un enlace a /etc/shadow no se lee), sin
bloquearse en FIFOs ni dispositivos (/dev/zero), solo ficheros normales y con un tamaño máximo.
Las comprobaciones se hacen sobre el descriptor ya abierto: no hay carrera entre comprobar y leer."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Iterable, Optional

MAX_TEXT = 1024 * 1024


class UnsafeFile(OSError):
    pass


def open_regular(path, owners: Optional[Iterable[int]] = None, no_group_write: bool = False) -> int:
    """Descriptor de un fichero normal. owners: uid aceptados como propietario."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError as e:
        if e.errno in (40,):                                   # ELOOP: es un enlace simbólico
            raise UnsafeFile(f"{path} es un enlace simbólico") from e
        raise
    st = os.fstat(fd)
    problem = ""
    if not stat.S_ISREG(st.st_mode):
        problem = f"{path} no es un fichero normal"
    elif owners is not None and st.st_uid not in set(owners):
        problem = f"{path} es de otro usuario"
    elif no_group_write and st.st_mode & 0o022:
        problem = f"{path} lo pueden modificar otros usuarios"
    if problem:
        os.close(fd)
        raise UnsafeFile(problem)
    return fd


def read_bytes(path, max_bytes: int = MAX_TEXT, **kw) -> bytes:
    fd = open_regular(path, **kw)
    with os.fdopen(fd, "rb") as fh:
        return fh.read(max_bytes)


def read_text(path, max_bytes: int = MAX_TEXT, **kw) -> str:
    return read_bytes(path, max_bytes, **kw).decode("utf-8", "replace")


def sha256(path, max_bytes: int = 1 << 34) -> tuple[str, int]:
    """(hash, bytes leídos) por bloques, sin cargar el fichero en memoria."""
    h, n = hashlib.sha256(), 0
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as fh:
        while n < max_bytes:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def copy(src, dst: Path, max_bytes: int, mode: int = 0o600) -> int:
    """Copia src (sin seguir enlaces) a dst, nuevo y solo para root. Devuelve los bytes copiados;
    si el origen es mayor que max_bytes se copia solo el principio."""
    fd = open_regular(src)
    n = 0
    with os.fdopen(fd, "rb") as fin, \
            os.fdopen(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as fout:
        while n < max_bytes:
            chunk = fin.read(min(1 << 20, max_bytes - n))
            if not chunk:
                break
            fout.write(chunk)
            n += len(chunk)
    return n
