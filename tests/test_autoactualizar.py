"""Pruebas de `opsdeck autoactualizar` con repositorios git reales (sin red).

El origen se declara https, como exige el actualizador, y la consulta al remoto se sustituye por un
fetch desde un repositorio local."""
import io
import subprocess

import pytest
from rich.console import Console

from opsdeck import cli
from opsdeck.core import system

GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *GIT_ID, *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def publish(repo, version_line, subject):
    (repo / "opsdeck" / "__init__.py").write_text(f'NAME = "opsdeck"\n{version_line}\n')
    (repo / "CAMBIOS").write_text(subject + "\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", subject)


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    upstream = tmp_path / "upstream"
    (upstream / "opsdeck").mkdir(parents=True)
    git(tmp_path, "init", "-q", "-b", "main", str(upstream))
    (upstream / "opsdeck" / "__init__.py").write_text('NAME = "opsdeck"\nVERSION = "2.4.2"\n')
    git(upstream, "add", ".")
    git(upstream, "commit", "-qm", "inicial")
    app = tmp_path / "app"
    subprocess.run(["git", "clone", "-q", str(upstream), str(app)], check=True)
    git(app, "remote", "set-url", "origin", "https://example.invalid/opsdeck.git")

    real_run = system.run

    def fake_run(cmd, **kw):
        if "fetch" in cmd:      # el remoto https no existe: se trae del repositorio local
            return real_run(["git", "-C", str(app), "fetch", "--quiet", str(upstream),
                             "+refs/heads/main:refs/remotes/origin/main"])
        return real_run(cmd, **kw)

    out = io.StringIO()
    monkeypatch.setattr(cli.paths, "APP_DIR", app)
    monkeypatch.setattr(cli.system, "run", fake_run)
    monkeypatch.setattr(cli, "VERSION", "2.4.2")
    monkeypatch.setattr(cli, "console", Console(file=out, width=200, color_system=None))
    monkeypatch.setattr(cli.audit, "record", lambda *a, **k: None)
    return upstream, app, out


def test_solo_muestra_version_actual_y_nueva(entorno):
    upstream, app, out = entorno
    publish(upstream, 'VERSION = "2.4.2"', "commit intermedio que no debe verse")
    publish(upstream, 'VERSION = "2.4.3"', "Merge pull request #9 from rama")
    assert cli.cmd_autoactualizar(yes=False) == 1        # sin terminal no se confirma
    text = out.getvalue()
    assert "Versión actual: 2.4.2" in text and "Versión nueva:  2.4.3" in text
    assert "commit intermedio" not in text and "Merge pull request" not in text
    assert git(app, "rev-parse", "HEAD") != git(upstream, "rev-parse", "HEAD")   # no ha tocado nada


def test_actualiza_al_commit_anunciado(entorno):
    upstream, app, out = entorno
    publish(upstream, 'VERSION = "2.4.3"', "nueva")
    assert cli.cmd_autoactualizar(yes=True) == 0
    assert git(app, "rev-parse", "HEAD") == git(upstream, "rev-parse", "HEAD")
    text = out.getvalue()
    assert "actualizado a la versión 2.4.3" in text
    assert "Fast-forward" not in text and "__init__.py" not in text


def test_al_dia(entorno):
    _, _, out = entorno
    assert cli.cmd_autoactualizar(yes=True) == 0
    assert "ya es la última versión" in out.getvalue()


def test_cambios_sin_subir_version(entorno):
    upstream, _, out = entorno
    publish(upstream, 'VERSION = "2.4.2"', "arreglo")
    assert cli.cmd_autoactualizar(yes=False) == 1
    rev = git(upstream, "rev-parse", "HEAD")[:7]
    assert f"Versión nueva:  2.4.2 (revisión {rev})" in out.getvalue()


@pytest.mark.parametrize("linea", [
    'VERSION = "[red]9.9.9[/red]"',
    'VERSION = "9.9.9\x1b[2J"',
    'VERSION = "9.9.9"; import os',
    'VERSION = open("/etc/shadow").read()',
])
def test_version_remota_no_confiable(entorno, linea):
    upstream, _, out = entorno
    publish(upstream, linea, "versión rara")
    assert cli.cmd_autoactualizar(yes=False) == 1
    text = out.getvalue()
    assert "9.9.9" not in text and "\x1b" not in text
    rev = git(upstream, "rev-parse", "HEAD")[:7]
    assert f"Versión nueva:  revisión {rev}" in text      # la revisión, no un texto ajeno


def test_origen_no_https(entorno):
    _, app, out = entorno
    git(app, "remote", "set-url", "origin", "git@example.invalid:opsdeck.git")
    assert cli.cmd_autoactualizar(yes=True) == 1
    assert "no es https" in out.getvalue()


def test_cambios_locales_no_se_pisan(entorno):
    upstream, app, out = entorno
    publish(upstream, 'VERSION = "2.4.3"', "nueva")
    (app / "opsdeck" / "__init__.py").write_text("modificado a mano\n")
    before = git(app, "rev-parse", "HEAD")
    assert cli.cmd_autoactualizar(yes=True) == 1
    assert git(app, "rev-parse", "HEAD") == before
    assert (app / "opsdeck" / "__init__.py").read_text() == "modificado a mano\n"
