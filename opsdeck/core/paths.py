"""Rutas de la herramienta. Código, datos, registros y configuración van separados
para que el repositorio nunca contenga datos del equipo donde se usa."""

import os
from pathlib import Path

from .. import NAME

APP_DIR = Path(__file__).resolve().parents[2]          # raíz del repositorio instalado
HELP_FILE = APP_DIR / "HELP.md"
CONF_FILE = Path(os.environ.get("OPSDECK_CONF", f"/etc/{NAME}/{NAME}.conf"))
DATA_DIR = Path(os.environ.get("OPSDECK_DATA", f"/var/lib/{NAME}"))
LOG_DIR = Path(os.environ.get("OPSDECK_LOG", f"/var/log/{NAME}"))
BACKUP_DIR = DATA_DIR / "backups"
REPORT_DIR = DATA_DIR / "informes"
AUDIT_LOG = LOG_DIR / "auditoria.log"


def ensure_private_dir(path: Path, mode: int = 0o700) -> Path:
    """Crea la carpeta solo para root (sin ACL heredadas de padres permisivos)."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    return path
