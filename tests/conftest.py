"""Configuración común de las pruebas: sin red. La interfaz no consulta el repositorio al abrirse."""
import os

os.environ.setdefault("OPSDECK_SIN_COMPROBAR_ACTUALIZACION", "1")
