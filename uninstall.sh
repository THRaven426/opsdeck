#!/usr/bin/env bash
# Desinstala opsdeck. Por defecto conserva configuración, datos y registros de auditoría.
#   sudo /opt/opsdeck/uninstall.sh            pregunta
#   sudo /opt/opsdeck/uninstall.sh --todo     borra también datos, registros y configuración
set -euo pipefail
NAME="opsdeck"
DEST="/opt/$NAME"; BIN="/usr/local/bin/$NAME"
CONF_DIR="/etc/$NAME"; DATA_DIR="/var/lib/$NAME"; LOG_DIR="/var/log/$NAME"
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"

ALL=0; [[ "${1:-}" == "--todo" ]] && ALL=1
echo "Se eliminará: $DEST y $BIN"
if (( ! ALL )); then
  read -rp "¿Borrar también datos, copias, registros de auditoría y configuración? [s/N] " a || a=""
  [[ "${a,,}" == s* ]] && ALL=1
fi
(( ALL )) && echo "Y además: $DATA_DIR $LOG_DIR $CONF_DIR"
read -rp "¿Desea continuar? [S/n] " a || a="n"
[[ -z "$a" || "${a,,}" == s* ]] || { echo "Cancelado."; exit 1; }

rm -f "$BIN"
# posible enlace de respaldo creado cuando sudo no incluía /usr/local/bin en secure_path
for d in /usr/sbin /usr/bin /sbin /bin; do
  [[ -L "$d/$NAME" && "$(readlink "$d/$NAME")" == "$BIN" ]] && rm -f "$d/$NAME"
done
rm -rf "$DEST"
if (( ALL )); then rm -rf "$DATA_DIR" "$LOG_DIR" "$CONF_DIR"; fi
echo "$NAME desinstalado.$( (( ALL )) || echo " Se conservan $DATA_DIR, $LOG_DIR y $CONF_DIR.")"
echo "Los paquetes que se instalaron para los módulos (xrdp, etc.) no se tocan."
# Las reglas de sudo concedidas con la herramienta siguen vigentes: se avisa, no se borran solas
shopt -s nullglob
rules=(/etc/sudoers.d/90-opsdeck-*)
if (( ${#rules[@]} )); then
  echo "AVISO: siguen activas estas reglas de sudo creadas con $NAME (bórralas si ya no deben existir):"
  printf '  %s\n' "${rules[@]}"
fi
