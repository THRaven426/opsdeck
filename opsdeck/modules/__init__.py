"""Registro de módulos. Para añadir uno: crea su fichero en esta carpeta y añádelo aquí.
El orden de la lista es el orden del menú dentro de cada categoría."""

from .almacenamiento import Almacenamiento
from .antimalware import Antimalware
from .bastionado import Bastionado
from .dominio import Dominio
from .escaneo import Escaneo
from .exposicion import Exposicion
from .firewall import Firewall
from .fuentes import Fuentes
from .informes import Informes
from .integridad import Integridad
from .ldap import Ldap
from .nuclei import Nuclei
from .rdp import EscritorioRemoto
from .red import Red
from .registros import Registros
from .revision import Revision
from .rootkits import Rootkits
from .servicios import Servicios
from .smb import Smb
from .ssh import Ssh
from .trafico import Trafico
from .sistema import Sistema
from .tls import Tls
from .triaje import Triaje
from .usuarios import Usuarios
from .web import Web

MODULES = [
    # Sistemas
    Sistema, Usuarios, Servicios, Registros, Red, Firewall, Almacenamiento, EscritorioRemoto, Dominio, Ldap,
    # Blue team
    Revision, Triaje, Bastionado, Antimalware, Rootkits, Integridad,
    # Ciberseguridad
    Escaneo, Exposicion, Tls, Ssh, Smb, Web, Nuclei, Trafico, Informes, Fuentes,
]
