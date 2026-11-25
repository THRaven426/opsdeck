"""Configuración en /etc/opsdeck/opsdeck.conf (formato INI). Si no existe se usan
los valores por defecto. Solo se carga si es de root y nadie más puede escribirla."""

from __future__ import annotations

import configparser
import os
import tempfile
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
    "verificacion": {
        # Consultar los avisos de Ubuntu/Debian (OSV) para saber si un CVE ya está corregido en un
        # paquete. Solo sale el identificador del CVE. false = usar solo lo que haya en caché.
        "consultar_osv": "true",
        # Servidor interactsh PROPIO e interno para las pruebas fuera de banda (Log4Shell, SSRF...).
        # Vacío = esas plantillas no se lanzan. Nunca se usan los servidores públicos.
        "interactsh_servidor": "",
    },
    "actualizacion": {
        # Comprobar al abrir la interfaz si hay una versión nueva (solo consulta; no instala nada).
        "comprobar_al_abrir": "true",
    },
    "interfaz": {
        "tema": "opsdeck",              # opsdeck | claro | contraste
    },
    "usuarios": {
        "shell": "/bin/bash",
        "longitud_password": "16",
        "minimo_password": "12",
        "grupos_privilegiados": "root sudo wheel admin adm docker lxd libvirt disk shadow kvm kali-trusted",
    },
}


def _safe(path) -> bool:
    """De root (o del propio usuario si se eligió otra ruta con OPSDECK_CONF) y que nadie más
    pueda escribirla: la configuración decide el alcance de red y quién usa la edición completa."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    owners = {0, os.geteuid()} if os.environ.get("OPSDECK_CONF") else {0}
    return st.st_uid in owners and not (st.st_mode & 0o022)


@lru_cache(maxsize=1)
def settings() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_dict(DEFAULTS)
    if paths.CONF_FILE.exists() and _safe(paths.CONF_FILE):
        cfg.read(paths.CONF_FILE, encoding="utf-8")
    return cfg


def save() -> None:
    """Escritura atómica: un fallo a mitad no deja la configuración vacía. Si el fichero actual se
    ignoró por inseguro no se sobrescribe: se perderían la edición y las redes autorizadas."""
    if paths.CONF_FILE.exists() and not _safe(paths.CONF_FILE):
        raise PermissionError(f"{paths.CONF_FILE} no es de root o lo pueden modificar otros: corrígelo "
                              f"(chown root:root, chmod 644) antes de guardar cambios")
    cfg = settings()
    paths.CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=paths.CONF_FILE.parent, prefix=".conf-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            cfg.write(f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, paths.CONF_FILE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
