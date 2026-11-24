#!/usr/bin/env bash
# =====================================================================
#  Instalador de opsdeck
#  Uso:   sudo ./install.sh          (pregunta antes de instalar nada)
#         sudo ./install.sh --si     (sin preguntas, para automatizar)
#         sudo ./install.sh --edicion ligera|completa
#  Ediciones:
#    ligera    administración diaria (usuarios, servicios, red, dominio...) y análisis básico
#    completa  además: tráfico, triaje de incidentes, auditoría de red y vulnerabilidades.
#              Sus módulos avanzados solo los usan los miembros del grupo opsdeck-completa.
#  Qué hace:
#   1. Comprueba qué falta (Python 3.10+, venv) y te lo muestra, como apt.
#   2. Copia la herramienta a /opt/opsdeck y crea su entorno Python aislado.
#   3. Crea el comando 'opsdeck', la configuración y las carpetas de datos.
#  No toca nada más del sistema. Para quitarla: sudo /opt/opsdeck/uninstall.sh
# =====================================================================
set -euo pipefail

NAME="opsdeck"
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/$NAME"
BIN="/usr/local/bin/$NAME"
CONF_DIR="/etc/$NAME"
DATA_DIR="/var/lib/$NAME"
LOG_DIR="/var/log/$NAME"
YES=0; EDITION=""; FULL_GROUP="opsdeck-completa"; ARGS=("$@")
while (( $# )); do
  case "$1" in
    --si|-y) YES=1 ;;
    --edicion|--edición) EDITION="${2:-}"; shift ;;
    --edicion=*) EDITION="${1#*=}" ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ -t 1 ]]; then B='\033[1m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
else B=''; G=''; Y=''; R=''; N=''; fi
say(){ echo -e "${G}==>${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
die(){ echo -e "${R}[x]${N} $*" >&2; exit 1; }
ask(){ (( YES )) && return 0; local a; read -rp "$* [S/n] " a || return 1; [[ -z "$a" || "${a,,}" == s* ]]; }

if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null || die "Hace falta ser root"
  exec sudo "$0" "$@"
fi

# ------------------------------------------------------------- sistema
# Se lee en un subproceso: /etc/os-release define NAME y pisaría el nombre de la herramienta.
OS_IDS="$( . /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}" )"
OS_PRETTY="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}" )"
FAMILY="desconocida"
case " $OS_IDS " in
  *" debian "*|*" ubuntu "*|*" kali "*) FAMILY="debian" ;;
  *" rhel "*|*" fedora "*|*" centos "*) FAMILY="rhel" ;;
  *" suse "*) FAMILY="suse" ;;
  *" arch "*) FAMILY="arch" ;;
esac
echo -e "${B}Instalación de $NAME${N} en $OS_PRETTY (familia: $FAMILY)"
[[ "$FAMILY" == debian ]] || warn "Esta distribución aún no está probada; se intentará igualmente."

# ------------------------------------------------------------- dependencias
PKGS=()
pkg_missing(){
  case "$FAMILY" in
    debian) ! dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    rhel|suse) ! rpm -q "$1" >/dev/null 2>&1 ;;
    arch) ! pacman -Q "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
py_ok(){ command -v python3 >/dev/null && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; }

case "$FAMILY" in
  debian) for p in python3 python3-venv; do pkg_missing "$p" && PKGS+=("$p"); done ;;
  rhel)   pkg_missing python3 && PKGS+=(python3) ;;
  suse)   pkg_missing python3 && PKGS+=(python3) ;;
  arch)   pkg_missing python && PKGS+=(python) ;;
  *)      py_ok || die "Instala Python 3.10 o superior y vuelve a ejecutar el instalador." ;;
esac

# ------------------------------------------------------------- edición
PREV="$(sed -n 's/^edicion *= *//p' "$CONF_DIR/$NAME.conf" 2>/dev/null | head -n 1 || true)"
if [[ -z "$EDITION" ]]; then
  if (( YES )) || [[ ! -t 0 ]]; then EDITION="${PREV:-ligera}"
  else
    echo
    echo "¿Qué edición quieres instalar?"
    echo "  1) ligera    administración diaria y análisis básico"
    echo "  2) completa  además: tráfico, incidentes, auditoría de red y vulnerabilidades (acceso restringido)"
    read -rp "Edición [${PREV:-ligera}]: " a || a=""
    case "${a,,}" in 1|ligera) EDITION=ligera ;; 2|completa) EDITION=completa ;; *) EDITION="${PREV:-ligera}" ;; esac
  fi
fi
[[ "$EDITION" == ligera || "$EDITION" == completa ]] || die "Edición no válida: $EDITION (ligera o completa)"

echo
echo -e "Edición: ${B}$EDITION${N}"
if (( ${#PKGS[@]} )); then
  echo "Se instalarán los siguientes paquetes del sistema:"
  echo "  ${PKGS[*]}"
fi
echo "Se creará:"
echo "  $DEST            la herramienta y su entorno Python (descarga 'textual' de PyPI, ~5 MB)"
echo "  $BIN   el comando '$NAME'"
echo "  $CONF_DIR, $DATA_DIR, $LOG_DIR   configuración, datos y registros (solo root)"
[[ "$EDITION" == completa ]] && echo "  grupo '$FULL_GROUP'   quien pertenezca a él puede usar los módulos avanzados"
echo
ask "¿Desea continuar?" || { echo "Cancelado: no se ha cambiado nada."; exit 1; }

if (( ${#PKGS[@]} )); then
  say "Instalando paquetes del sistema"
  case "$FAMILY" in
    debian) DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS[@]}" ;;
    rhel)   dnf install -y "${PKGS[@]}" ;;
    suse)   zypper --non-interactive install "${PKGS[@]}" ;;
    arch)   pacman -S --noconfirm --needed "${PKGS[@]}" ;;
  esac
fi
py_ok || die "Hace falta Python 3.10 o superior (tienes $(python3 --version 2>&1))."

# ------------------------------------------------------------- copia
if [[ "$SRC" != "$DEST" ]]; then
  say "Copiando la herramienta a $DEST"
  mkdir -p "$DEST"
  # se conserva .git (para actualizar) y nunca se copian entornos ni cachés
  tar -C "$SRC" --exclude-vcs-ignores --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache --exclude=.ruff_cache -cf - . | tar -C "$DEST" -xf -
fi
chown -R root:root "$DEST"
chmod -R u=rwX,go=rX "$DEST"
chmod 755 "$DEST/install.sh" "$DEST/uninstall.sh"

say "Creando el entorno Python"
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install -q --upgrade pip
"$DEST/.venv/bin/pip" install -q -r "$DEST/requirements.txt"

say "Creando el comando $NAME"
cat > "$BIN" <<EOF
#!/bin/sh
# Lanzador de $NAME: se relanza con sudo si hace falta y usa su entorno Python aislado.
if [ "\$(id -u)" -ne 0 ]; then exec sudo "\$0" "\$@"; fi
# -I: aislado; ni el directorio actual ni las variables PYTHON* pueden colar código que se ejecute como root
exec "$DEST/.venv/bin/python" -I -c 'import sys; sys.path.insert(0, "$DEST"); from $NAME.cli import main; sys.exit(main(sys.argv[1:]))' "\$@"
EOF
chmod 755 "$BIN"

# Si sudo restringe el PATH (secure_path) y no incluye /usr/local/bin, 'sudo opsdeck' daría
# "command not found". El lanzador ya se eleva solo (basta 'opsdeck' sin sudo), pero por si
# alguien escribe 'sudo opsdeck', dejamos también un enlace donde sudo sí busca.
link_for_sudo(){
  local sp line dir
  line="$(grep -rhsE '^[[:space:]]*Defaults[[:space:]]+.*secure_path' /etc/sudoers /etc/sudoers.d 2>/dev/null | tail -n1)" || true
  [[ -z "$line" ]] && return 0
  sp="${line#*secure_path}"; sp="${sp#*=}"; sp="${sp%\"}"; sp="${sp#\"}"; sp="${sp%\'}"; sp="${sp#\'}"
  case ":$sp:" in *":/usr/local/bin:"*) return 0 ;; esac
  for dir in /usr/sbin /usr/bin /sbin /bin; do
    case ":$sp:" in
      *":$dir:"*) ln -sf "$BIN" "$dir/$NAME" 2>/dev/null &&
          warn "sudo no incluye /usr/local/bin en secure_path; enlazado también en $dir/$NAME"
          return 0 ;;
    esac
  done
  return 0
}
link_for_sudo

say "Preparando configuración y carpetas"
install -d -m 755 "$CONF_DIR"
install -d -m 750 "$DATA_DIR" "$LOG_DIR"
if [[ ! -f "$CONF_DIR/$NAME.conf" ]]; then
  install -m 644 "$DEST/$NAME.conf.example" "$CONF_DIR/$NAME.conf"
fi
if grep -q '^edicion *=' "$CONF_DIR/$NAME.conf"; then
  sed -i "s/^edicion *=.*/edicion = $EDITION/" "$CONF_DIR/$NAME.conf"
elif grep -q '^\[general\]' "$CONF_DIR/$NAME.conf"; then
  sed -i "/^\[general\]/a edicion = $EDITION" "$CONF_DIR/$NAME.conf"
else
  printf '\n[general]\nedicion = %s\n' "$EDITION" >> "$CONF_DIR/$NAME.conf"
fi
if [[ "$EDITION" == completa ]]; then
  getent group "$FULL_GROUP" >/dev/null || groupadd "$FULL_GROUP"
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    gpasswd -a "$SUDO_USER" "$FULL_GROUP" >/dev/null
    say "Edición completa: $SUDO_USER añadido al grupo $FULL_GROUP"
  fi
fi

echo
"$BIN" --version >/dev/null && say "${B}$NAME instalado.${N}"
echo "  Abrir:        $NAME            (pide la contraseña de sudo él solo; no escribas 'sudo $NAME')"
echo "  Ayuda:        $NAME ayuda      (dentro de la herramienta: tecla ?)"
echo "  Módulos:      $NAME modulos        (instalar todas las herramientas: $NAME instalar todo)"
[[ "$EDITION" == completa ]] && echo "  Dar acceso a la edición completa: sudo gpasswd -a <usuario> $FULL_GROUP"
echo "  Desinstalar:  sudo $DEST/uninstall.sh"
