# Registro de cambios

Las versiones anteriores a la 2.4.2 están descritas en
[Releases](https://github.com/THRaven426/opsdeck/releases).

## 2.5.0 — 2026-11-25 — Verificación de vulnerabilidades e interfaz nueva

Versión con funciones nuevas. No cambia el lanzador ni los permisos: basta con actualizar. Desde la
2.4.x se actualiza una última vez con `opsdeck autoactualizar`; a partir de la 2.5.0, también desde la
propia interfaz (tecla `u`).

### Verificación de vulnerabilidades (módulo nuevo, edición completa)

- Confirma o descarta de forma segura los CVE que marcan los análisis, para quitar falsos positivos.
  Cada CVE recibe un veredicto: **CONFIRMADA**, **NO APLICA**, **NO REPRODUCIDA** o **NO CONCLUYENTE**,
  con la prueba que lo decide y sus evidencias.
- **Paquetes de la distribución (backports):** compara la versión del paquete (del banner, indicada a
  mano o, con el objetivo `local`, la instalada en este equipo) con la versión en la que Ubuntu o
  Debian publicó la corrección (avisos OSV). Es el falso positivo más habitual de Nessus, OpenVAS y
  vulners: «OpenSSH 9.6p1 es vulnerable» cuando el paquete ya lleva el parche. Solo sale el
  identificador del CVE; caché local de 3 días y opción `[verificacion] consultar_osv`.
- **nuclei:** solo las plantillas seguras de ese CVE (nunca `dos`, `fuzz`, `intrusive`, `brute-force`,
  `default-login` ni DAST; nunca de tipo `code`, `headless`, `javascript` o `file`), a 10 peticiones por
  segundo. Las plantillas `rce` solo con permiso expreso.
- **nmap:** solo los scripts NSE de ese CVE clasificados a la vez como `vuln` y `safe`.
- Pruebas fuera de banda (interactsh) desactivadas por defecto; solo con un servidor propio e interno
  (`[verificacion] interactsh_servidor`). Se rechazan los servidores públicos.
- Verificación por lotes de los CVE del último análisis de nuclei, del último escaneo (vulners) o de
  un informe de Nessus/OpenVAS importado, también desde *Resultados* con el botón *Verificar hallazgos*.
- Cada verificación se guarda en su propia carpeta; el análisis de origen solo se lee.

### Interfaz nueva

- **Panel de inicio** con el estado del equipo, de la herramienta, del alcance autorizado, de las
  fuentes de datos, de los módulos y los últimos resultados, y accesos rápidos.
- **Búsqueda rápida** (tecla `/`) de cualquier módulo o acción, sin importar tildes.
- Vista de módulo con **vista previa de la acción** (qué hace, qué pide, si cambia el sistema y su orden
  de línea de comandos) y pestañas **Salida**, **Resultados del módulo** y **Ayuda del módulo**.
- Indicador de ejecución con tiempo transcurrido, colores por veredicto y severidad en las tablas
  (siempre con símbolo o texto, no solo color) y tres temas: oscuro, claro y alto contraste (tecla `t`).

### Actualización integrada

- Al abrir la interfaz se comprueba si hay una versión nueva (solo consulta; se puede desactivar con
  `[actualizacion] comprobar_al_abrir`). Si la hay, se avisa en una barra y en el panel de inicio.
- Tecla `u`: ventana con la versión instalada y la nueva y el registro de cambios (informativo), botón
  para instalar con el progreso a la vista y, al terminar, reinicio de la herramienta. Si el
  instalador ha cambiado, se aplica (`install.sh --si`) antes de volver a abrirla.
- Misma lógica que `opsdeck autoactualizar` (que sigue funcionando): solo https, sin hooks de git,
  exactamente el commit anunciado y vuelta atrás si fallan las dependencias. El texto que llega del
  repositorio se limpia de secuencias de terminal antes de mostrarse.

## 2.4.3 — 2026-11-25 — Aviso de actualización más claro

Versión de parche. No cambia los módulos, la configuración ni el lanzador.

- `autoactualizar` ya no lista los commits pendientes: solo indica la versión instalada y la nueva antes
  de pedir confirmación, e instala exactamente el commit anunciado. El número de versión remoto se lee
  como texto y solo se muestra si tiene forma de versión; si no cambia, se indica la revisión.

## 2.4.2 — 2026-11-24 — Revisión de seguridad

Versión de correcciones: tres rondas de revisión de seguridad y funcionamiento e integración continua.
No cambia los módulos ni la configuración.

> [!IMPORTANT]
> **Después de actualizar hay que ejecutar una vez `sudo /opt/opsdeck/install.sh`**, porque el lanzador
> `opsdeck` ha cambiado y `autoactualizar` no lo renueva. Ver [Actualizar](README.md#actualizar).

### Ejecución como root

- **Corregido:** el lanzador ejecuta Python en modo aislado (`python -I`) y con entorno limpio: el
  directorio actual ya no puede inyectar módulos que se ejecuten como root.
- **Corregido:** altas y bajas en `authorized_keys` sobre descriptores con `O_NOFOLLOW`, sin carrera de
  enlaces simbólicos como root; lectura segura (sin enlaces, comprobando propietario y tamaño) de los
  ficheros de usuarios que se leen como root.
- **Corregido:** restablecer contraseñas respeta la protección de root y de las cuentas de sistema; nombres
  reservados y grupos críticos protegidos contra la autoasignación; el operador se toma de `loginuid`.
- Reglas de sudoers con nombre válido para usuarios con punto; los nombres que empiezan por `-` ya no
  llegan como opción a `realm`, `id` o `getent`.
- `install.sh` y `uninstall.sh` no pisan ni borran un `opsdeck` ajeno; la copia excluye lo ignorado por git
  y `.git` se instala sin hooks.
- `autoactualizar` solo acepta un origen https, no ejecuta hooks de git y vuelve a la versión anterior si
  falla la actualización del entorno Python.

### Alcance y entradas no confiables

- Un rango solo cuenta como dentro del alcance si cabe entero en una red autorizada (o en redes
  contiguas); las listas de objetivos en fichero se validan, deben ser de root o del operador y su
  contenido no se repite en la auditoría.
- Las opciones adicionales de nmap y nuclei no admiten ficheros, rutas ni objetivos fuera de alcance
  (también en forma larga, como `--oA` o `--iL`); nuclei bloquea `-config` y `uncover`.
- LDAP verifica el certificado por defecto (opción `ca`) y el servidor tiene que estar dentro del alcance.
- Secretos fuera de la línea de órdenes: enum4linux solo anónimo, netexec y el hash NT por fichero privado
  que siempre se borra, `--password -` pide la contraseña sin eco; secretos ocultos en `orden.txt`, en
  pantalla y en la auditoría.
- XML de terceros con `defusedxml`; CSV a prueba de fórmulas; datos externos escapados antes de pasarlos a
  Rich; en los informes se descartan equipos que no son IP ni nombre válido.
- El cortafuegos no deja fuera el acceso remoto en uso y protege los servicios críticos.
- Configuración: comprobación de propietario también con `OPSDECK_CONF`, sin interpolación de `%` y
  guardado atómico.

### Correcciones

- Resolución de nombres con IPv4 e IPv6 a la vez (fallaba con equipos de doble pila).
- `PORTS` «todos», `--script-args` combinados, puertos y `shadow` mal formados, testssl con IPv6, permisos
  de AIDE y del registro rotado.

### Desarrollo

- Dependencias de Python fijadas con versión y hash (`pip --require-hashes`) en el instalador, la
  actualización y CI.
- Integración continua en GitHub Actions: ruff y sintaxis de los scripts; pytest en Python 3.10 a 3.13
  (como root, igual que en el README).
- Pruebas que ya no salen a la red ni dependen de las herramientas instaladas, y pruebas nuevas de
  seguridad y de regresión.
