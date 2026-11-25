# Registro de cambios

Las versiones anteriores a la 2.4.2 están descritas en
[Releases](https://github.com/THRaven426/opsdeck/releases).

## Sin publicar

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
