# Ayuda de opsdeck

opsdeck reúne en una sola herramienta las tareas habituales de **sistemas** y de
**ciberseguridad** en Linux. Está pensada para que cualquier persona de IT la pueda usar,
sepa o no de comandos.

## Abrir la herramienta

```
sudo opsdeck
```

Si la abres sin `sudo`, se relanza sola con sudo y te pide tu contraseña.

## Cómo se usa

| Tecla | Qué hace |
|---|---|
| ↑ ↓ e Intro | Moverse y elegir (también con el ratón) |
| Tab | Pasar de la lista de módulos a la de acciones |
| **?** | **Ayuda de lo que tengas seleccionado**: módulo, acción o esta guía |
| c | Catálogo: todos los módulos y su estado |
| r | Volver a detectar qué hay instalado en el equipo |
| g | Resultados guardados: escaneos, análisis, revisiones, evidencias |
| l | Registro de cambios (quién hizo qué y cuándo) |
| s | Detener la acción en curso (escaneos y análisis largos) |
| q | Salir |

**En los formularios:** Intro = aceptar · Esc = cancelar · **F1 = ayuda** de esa acción ·
Espacio = marcar o desmarcar casillas.

1. Elige un **módulo** a la izquierda.
2. Elige una **acción**. Las marcadas con **●** cambian algo en el sistema.
3. Si necesita datos, se abre un formulario. Las acciones delicadas piden confirmación.
4. El resultado aparece en el panel inferior.

## Ediciones

- **Ligera**: administración diaria (todo *Sistemas*), la *Revisión de seguridad* y el escaneo de red básico.
- **Completa**: además, tráfico, triaje de incidentes, bastionado, antimalware, auditoría de SMB,
  web y vulnerabilidades. Estos módulos solo los usan los miembros del grupo `opsdeck-completa`.

`opsdeck edicion` dice cuál tienes y quién tiene acceso. Se cambia con
`sudo ./install.sh --edicion completa` (o `ligera`). En el Catálogo, lo que no es de tu edición o
no tienes permiso para usar aparece como "no aplica" con el motivo.

> La edición completa es potente: úsala solo sobre sistemas propios o con autorización por escrito.

## Qué hay en cada sección

**Sistemas** (administración del día a día)

| Módulo | Para qué sirve |
|---|---|
| Sistema | Vistazo rápido al equipo y actualizaciones |
| Usuarios | Cuentas locales, contraseñas, grupos, sudo, claves SSH e inventario |
| Servicios | Ver, arrancar, parar y reiniciar servicios; tareas programadas |
| Registros | Errores recientes, accesos fallidos y correctos, uso de sudo, búsqueda |
| Red | Interfaces, conexiones y "no llego a tal servidor" |
| Firewall | Qué puertos se pueden alcanzar desde la red |
| Almacenamiento | Discos llenos: qué ocupa y qué se puede limpiar |
| Escritorio remoto | Quién entra por RDP y por qué alguien no puede |
| Dominio | Unir el equipo a Active Directory y dejarlo seguro según cada caso |
| LDAP / Active Directory | Consultar el directorio y revisar su seguridad |

**Blue team** (defensa)

| Módulo | Para qué sirve |
|---|---|
| Revisión de seguridad | Los fallos más habituales, sin instalar nada, comparados con la vez anterior |
| Triaje de incidentes | "¿Me han entrado?": persistencia, procesos raros, evidencias |
| Bastionado (Lynis) | Auditoría profunda con nota de 0 a 100 |
| Antimalware (ClamAV) | Buscar malware en carpetas |
| Rootkits (rkhunter) | Buscar rootkits y binarios alterados |
| Integridad (AIDE) | Qué ficheros del sistema han cambiado |

**Ciberseguridad** (auditoría de red; solo con autorización)

| Módulo | Para qué sirve |
|---|---|
| Escaneo de red | Qué equipos y servicios hay, y qué ha cambiado desde el último escaneo |
| Tráfico de red | Capturar y resumir tráfico; ver qué equipos hay sin enviar nada a la red |
| SMB y Windows | SMBv1, firma SMB y recursos compartidos accesibles |
| Web y TLS | Certificados que caducan, TLS obsoleto, cabeceras; de una web o de todas |
| Vulnerabilidades (nuclei) | Vulnerabilidades conocidas comprobadas de verdad |

Algunos módulos dependen de programas que quizá no tengas: aparecen en el *Catálogo* para
instalarlos cuando los necesites.

## El menú se adapta al equipo

Cada vez que abres opsdeck se comprueba qué hay instalado. Solo ves los módulos que
funcionan en este equipo: si no hay servidor de escritorio remoto, no aparece *Escritorio remoto*.
Si lo instalas mañana, aparecerá solo. Con la herramienta abierta, pulsa **r**.

En el **Catálogo** (tecla **c**) están todos los módulos:

- **✓ disponible**: aparece en el menú.
- **⬇ se puede instalar**: falta algún programa. Pulsa **i** y verás qué se va a instalar y
  cuánto ocupa, igual que con `apt`. No se instala nada sin tu confirmación.
- **— no aplica**: no se puede usar en este equipo (por ejemplo, otra distribución).

Desde el catálogo también puedes **ocultar** módulos que no uses (tecla **v**).

## Usarla desde la línea de comandos

Todo lo que hace el menú se puede hacer en una línea. Sirve para expertos y para automatizar.

```
opsdeck modulos                                  # catálogo y estado
opsdeck ayuda usuarios                           # ayuda de un módulo y sus acciones
opsdeck ayuda usuarios crear                     # qué datos pide una acción
opsdeck usuarios ficha jperez                    # ejecutar una acción
opsdeck usuarios crear --usuario jperez --nombre "Juan Pérez" --grupos sudo --no-forzar
opsdeck usuarios bloquear jperez --si            # --si confirma sin preguntar
opsdeck instalar rdp                             # instalar lo que le falta a un módulo
opsdeck instalar todo                            # todas las herramientas de tu edición, de una vez
opsdeck edicion                                  # edición instalada y quién accede a la completa
opsdeck registro 20 jperez                       # últimos 20 cambios que mencionan a jperez
opsdeck resultados escaneo                       # escaneos guardados
opsdeck revision revisar                         # revisión de seguridad completa
opsdeck escaneo escanear --objetivo 192.168.0.0/24 --perfil rapido
opsdeck autoactualizar                           # actualizar la herramienta (si se instaló con git)
```

Si falta un dato obligatorio y estás en una terminal, te lo pregunta.

## Dónde guarda las cosas

| Qué | Dónde |
|---|---|
| La herramienta | `/opt/opsdeck` |
| Configuración | `/etc/opsdeck/opsdeck.conf` (comentada, con todos los valores) |
| Registro de cambios | `/var/log/opsdeck/auditoria.log` y `journalctl -t opsdeck` |
| Copias previas a cambios de cuentas | `/var/lib/opsdeck/backups` (solo root) |
| Resultados (escaneos, análisis, evidencias) | `/var/lib/opsdeck/resultados` (solo root; tecla **g**) |
| Informes CSV | `/var/lib/opsdeck/informes` |

El registro rota solo al llegar a 1 MB y conserva 5 ficheros comprimidos. De cada módulo se
conservan los 50 resultados más recientes. Todo se ajusta en la configuración. Las contraseñas
**nunca** se registran ni se guardan.

## Seguridad

- Las contraseñas generadas se muestran **una sola vez** y no se guardan en ningún sitio.
- Antes de cada cambio en cuentas se guarda copia de `passwd`, `shadow`, `group` y `sudoers`.
- No permite bloquear, borrar ni quitar sudo a **tu propia cuenta**, ni tocar root o las cuentas de sistema.
- Para eliminar un usuario hay que escribir otra vez su nombre, y antes se guarda copia de su carpeta.

## Preguntas frecuentes

**No veo un módulo que esperaba.** Abre el *Catálogo* (**c**): verás si falta algo
y podrás instalarlo, o si lo has ocultado.

**Algo no funciona y no sé por dónde empezar.** *Registros › Errores recientes* y
*Servicios › Estado y registros de un servicio* suelen dar la pista.

**Sospecho que intentan entrar por fuerza bruta.** *Registros › Accesos fallidos* agrupa los intentos
por IP de origen y por usuario.

**Se ha llenado un disco.** *Almacenamiento › Qué ocupa más* y baja de carpeta en carpeta.

**Un usuario no puede entrar por escritorio remoto.** *Escritorio remoto › Diagnosticar un usuario*
te dice exactamente por qué. Lo más habitual: tiene pendiente el cambio de contraseña
(xrdp no sabe pedirlo) o la escribió mal.

**¿Cómo deshago un cambio?** Casi todo tiene su acción contraria: bloquear/desbloquear,
dar/quitar sudo, añadir/quitar de grupo. Para casos graves hay copias de las cuentas en
`/var/lib/opsdeck/backups`.

**La acción dice que necesita root.** Abre la herramienta con `sudo opsdeck`.
