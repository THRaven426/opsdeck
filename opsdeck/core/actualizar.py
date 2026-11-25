"""Actualización de la propia herramienta desde su repositorio git (https).

Lo usan la interfaz visual (comprobación al abrir, ventana con los cambios, progreso y reinicio) y
`opsdeck autoactualizar`. Las dos vías hacen exactamente lo mismo:

1. comprobar(): consulta el remoto y fija el commit que se anuncia; no cambia nada instalado.
2. instalar(): avanza a ESE commit (solo fast-forward), reinstala las dependencias con hashes fijados
   y, si eso falla, vuelve a la versión anterior.

Todo lo que llega del remoto (número de versión, CHANGELOG) se trata como texto no confiable: se lee
con `git show`, sin importar ni ejecutar nada, y se limpia antes de mostrarlo. Git se ejecuta como
root sin hooks, sin fsmonitor y solo por https."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import audit, paths, system

VERSION_RE = re.compile(r'^VERSION\s*=\s*"(\d{1,4}(?:\.\d{1,4}){1,3})"\s*$', re.M)
_SHA_RE = re.compile(r"[0-9a-f]{40,64}")
# Caracteres de control (salvo salto de línea y tabulador) y secuencias de escape del terminal
_CTRL_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]|[\x00-\x08\x0b-\x1f\x7f\u0080-\u009f‪-‮⁦-⁩]")
CHANGELOG_MAX = 40_000      # caracteres del registro de cambios que se muestran como máximo

# Estados de comprobar()
AL_DIA, HAY_NUEVA, NO_GIT, ERROR = "al_dia", "hay_nueva", "no_git", "error"


@dataclass
class Estado:
    estado: str
    actual: str
    nueva: str = ""                # número de versión remoto (solo si tiene forma de versión)
    revision: str = ""             # commit remoto fijado (el que se instala)
    mensaje: str = ""
    cambios: str = ""              # extracto del CHANGELOG remoto, ya limpio

    @property
    def hay_nueva(self) -> bool:
        return self.estado == HAY_NUEVA

    @property
    def nueva_texto(self) -> str:
        """Cómo se muestra la versión nueva: el número o, si no cambia o no es fiable, la revisión."""
        if self.nueva and self.nueva != self.actual:
            return self.nueva
        if self.nueva:
            return f"{self.nueva} (revisión {self.revision[:7]})"
        return f"revisión {self.revision[:7]}"


@dataclass
class Resultado:
    ok: bool
    mensaje: str
    nueva: str = ""
    instalador_cambiado: bool = False
    revertido: bool = False
    detalle: list[str] = field(default_factory=list)


def git_cmd() -> list[str]:
    # Como root, git no debe ejecutar nada del repositorio: ni hooks, ni fsmonitor, ni otro ssh.
    return ["git", "-C", str(paths.APP_DIR), "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "core.sshCommand=ssh", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]


def limpiar(texto: str, limite: int = CHANGELOG_MAX) -> str:
    """Texto remoto apto para la pantalla: sin escapes de terminal ni controles, y acotado."""
    t = _CTRL_RE.sub("", texto.replace("\r\n", "\n").replace("\r", "\n"))
    if len(t) > limite:
        t = t[:limite].rsplit("\n", 1)[0] + "\n\n…(recortado)"
    return t


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split(".")) if re.fullmatch(r"\d{1,4}(\.\d{1,4}){0,3}", v or "") else ()


def extracto_changelog(texto: str, actual: str) -> str:
    """Secciones del CHANGELOG más nuevas que la versión instalada (encabezados «## X.Y.Z ...»).
    Si no se reconoce ninguna, el principio del fichero."""
    texto = limpiar(texto, 10 * CHANGELOG_MAX)
    cur = _version_tuple(actual)
    partes = re.split(r"(?m)^(?=## )", texto)
    nuevas = []
    for p in partes:
        m = re.match(r"## \[?v?(\d{1,4}(?:\.\d{1,4}){1,3})", p)
        if not m:
            continue
        if cur and _version_tuple(m.group(1)) <= cur:
            break
        nuevas.append(p.rstrip())
    out = "\n\n".join(nuevas) if nuevas else texto.strip()
    return limpiar(out)


def _remote_version(git: list[str], rev: str) -> str:
    """Número de versión de la revisión remota, leído como texto (sin importar ni ejecutar nada)."""
    r = system.run(git + ["show", f"{rev}:opsdeck/__init__.py"])
    m = VERSION_RE.search(r.out) if r.ok else None
    return m.group(1) if m else ""


def comprobar(actual: str, fetch: bool = True, timeout: int = 60) -> Estado:
    """¿Hay versión nueva? Solo consulta: no cambia nada de la instalación."""
    repo = paths.APP_DIR
    if not (repo / ".git").exists():
        return Estado(NO_GIT, actual, mensaje="Esta instalación no viene de un repositorio git. Para actualizar: "
                      "descarga la versión nueva y ejecuta de nuevo install.sh (conserva configuración y datos).")
    if not system.has_cmd("git"):
        return Estado(ERROR, actual, mensaje="Falta git: instálalo (apt install git) o actualiza con install.sh.")
    git = git_cmd()
    url = system.run(git + ["remote", "get-url", "origin"]).out.strip()
    if not url.startswith("https://"):
        return Estado(ERROR, actual, mensaje=f"El repositorio de origen no es https ({limpiar(url, 200) or 'sin origen'}): "
                      "se actualiza solo desde https. Descarga la versión nueva y ejecuta install.sh.")
    if fetch:
        r = system.run(git + ["fetch", "--quiet", "origin"], timeout=timeout,
                       env={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false"})
        if not r.ok:
            return Estado(ERROR, actual, mensaje="No se pudo consultar el repositorio remoto:\n" + limpiar(r.text, 1500))
    # Se fija el commit remoto una vez: lo que se anuncia es exactamente lo que se instala.
    up = system.run(git + ["rev-parse", "--verify", "--quiet", "@{u}^{commit}"])
    target = up.out.strip()
    if not up.ok or not _SHA_RE.fullmatch(target):
        return Estado(ERROR, actual, mensaje="La instalación no sigue ninguna rama remota:\n" + limpiar(up.text, 800))
    count = system.run(git + ["rev-list", "--count", f"HEAD..{target}"])
    if not count.ok:
        return Estado(ERROR, actual, mensaje="No se pudo comparar con la versión remota:\n" + limpiar(count.text, 800))
    if count.out.strip() == "0":
        return Estado(AL_DIA, actual, revision=target, mensaje=f"{actual} ya es la última versión.")
    nueva = _remote_version(git, target)
    log = system.run(git + ["show", f"{target}:CHANGELOG.md"])
    cambios = extracto_changelog(log.out, actual) if log.ok else ""
    return Estado(HAY_NUEVA, actual, nueva, target, "Hay una versión nueva.", cambios)


def instalar(estado: Estado, on_line: Optional[Callable[[str], None]] = None) -> Resultado:
    """Instala exactamente la revisión que anunció comprobar(). Vuelve atrás si fallan las dependencias."""
    say = on_line or (lambda _l: None)
    if not estado.hay_nueva or not _SHA_RE.fullmatch(estado.revision or ""):
        return Resultado(False, "No hay ninguna versión nueva comprobada que instalar.")
    git = git_cmd()
    before = system.run(git + ["rev-parse", "HEAD"]).out.strip()
    say(f"Avanzando a la revisión {estado.revision[:10]}…")
    r = system.run(git + ["merge", "--ff-only", "--quiet", estado.revision])
    if not r.ok:
        return Resultado(False, "No se pudo actualizar (¿hay cambios locales en la instalación?):\n" + limpiar(r.text, 1500))
    changed = system.run(git + ["diff", "--name-only", before, "HEAD"]).out.split()
    say(f"{len(changed)} ficheros actualizados.")
    pip = paths.APP_DIR / ".venv" / "bin" / "pip"
    if pip.exists():
        say("Actualizando el entorno Python (versiones y hashes fijados)…")
        r = system.run([str(pip), "install", "-q", "--require-hashes", "--no-deps", "-r",
                        str(paths.APP_DIR / "requirements.txt")], timeout=600)
        if not r.ok:
            system.run(git + ["reset", "--hard", "--quiet", before])
            audit.record("autoactualizar", "opsdeck", "REVERTIDO", "fallaron las dependencias")
            return Resultado(False, "No se pudieron instalar las dependencias (¿hash distinto o sin red?):\n"
                             + limpiar(r.text, 1500) + f"\nSe ha vuelto a la versión anterior ({before[:10]}).",
                             revertido=True)
    audit.record("autoactualizar", "opsdeck", "OK", f"{estado.actual} -> {estado.nueva or 'desconocida'}")
    return Resultado(True, f"opsdeck actualizado a la versión {estado.nueva or 'nueva'}.", estado.nueva,
                     "install.sh" in changed, detalle=changed)


def argv_reinicio() -> list[str]:
    """Orden para volver a abrir la herramienta con el código nuevo, igual que el lanzador
    (Python aislado con -I y la carpeta de la instalación como única ruta añadida)."""
    code = (f"import sys; sys.path.insert(0, {str(paths.APP_DIR)!r}); "
            "from opsdeck.cli import main; sys.exit(main(sys.argv[1:]))")
    return [sys.executable, "-I", "-c", code]
