"""Configuración en /etc/opsdeck/opsdeck.conf (formato INI). Si no existe se usan
los valores por defecto. Solo se carga si es de root y nadie más puede escribirla."""

from __future__ import annotations

import configparser
import os
from functools import lru_cache

from . import paths

DEFAULTS = {
    "general": {
        "modulos_ocultos": "",          # ids separados por coma
        "edicion": "ligera",            # ligera | completa (lo fija el instalador)
        "grupo_completa": "opsdeck-completa",
    },
    "auditoria": {
        "fichero": "true",
        "syslog": "true",
        "max_kb": "1024",
        "conservar": "5",
    },
    "copias": {
        "cuentas": "true",               # copia de passwd/shadow/... antes de cada cambio
        "conservar": "10",
    },
    "resultados": {
        "conservar_por_modulo": "50",   # escaneos/análisis guardados por módulo (los más antiguos se borran)
    },
    "red": {
        # Redes (CIDR) sobre las que SÍ está autorizado escanear y probar, además de las
        # subredes a las que este equipo está conectado. Separadas por coma o espacio.
        "redes_autorizadas": "",
        # true = ignorar las subredes locales y permitir SOLO las de redes_autorizadas.
        "solo_configuradas": "false",
    },
    "usuarios": {
        "shell": "/bin/bash",
        "longitud_password": "16",
        "minimo_password": "12",
        "grupos_privilegiados": "root sudo wheel admin adm docker lxd libvirt disk shadow kvm kali-trusted",
    },
}


def _safe(path) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not (st.st_mode & 0o022)


@lru_cache(maxsize=1)
def settings() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict(DEFAULTS)
    if paths.CONF_FILE.exists() and (_safe(paths.CONF_FILE) or os.environ.get("OPSDECK_CONF")):
        cfg.read(paths.CONF_FILE, encoding="utf-8")
    return cfg


def save() -> None:
    cfg = settings()
    paths.CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(paths.CONF_FILE, "w", encoding="utf-8") as f:
        cfg.write(f)
    os.chmod(paths.CONF_FILE, 0o644)


def set_value(section: str, option: str, value: str) -> None:
    cfg = settings()
    if not cfg.has_section(section):
        cfg.add_section(section)
    cfg.set(section, option, value)
    save()


def hidden_modules() -> set[str]:
    return {m.strip() for m in settings().get("general", "modulos_ocultos").split(",") if m.strip()}


def set_hidden(module_id: str, hidden: bool) -> None:
    current = hidden_modules()
    (current.add if hidden else current.discard)(module_id)
    settings().set("general", "modulos_ocultos", ",".join(sorted(current)))
    save()
