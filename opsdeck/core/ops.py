"""Ejecución de cambios: cada cambio pasa por apply(), que lo ejecuta, lo muestra
y lo deja en el registro de auditoría. Las acciones no llaman a subprocess directamente."""

from __future__ import annotations

from typing import Optional

from . import audit, system
from .catalog import Action, Context, Module


def apply(ctx: Context, accion: str, objetivo: str, cmd: list[str], detalle: str = "",
          input: Optional[str] = None, quiet: bool = False) -> bool:
    r = system.run(cmd, input=input)
    if r.ok:
        audit.record(accion, objetivo, "OK", detalle)
        if r.text and not quiet:
            for line in r.text.splitlines():
                ctx.out.line("    " + line)
        return True
    audit.record(accion, objetivo, f"ERROR_{r.rc}", detalle)
    ctx.out.error(f"Falló: {cmd[0]} (código {r.rc})")
    for line in r.text.splitlines()[-10:]:
        ctx.out.line("    " + line)
    return False


def stream(ctx: Context, cmd: list[str], *, accion: str = "", objetivo: str = "", detalle: str = "",
           save_to=None, input: Optional[str] = None, env: Optional[dict] = None,
           show: bool = True, keep: int = 0, ok_rc: tuple[int, ...] = (0,), cwd=None) -> tuple[int, str]:
    """Ejecuta un proceso largo mostrando la salida en vivo. Si se indica 'accion' queda en la
    auditoría (también los escaneos: quién analizó qué). 'save_to' guarda la salida completa.
    keep>0 limita las líneas que se muestran (las demás se guardan igualmente).
    ok_rc: códigos de salida que cuentan como «terminó bien» en la auditoría (p. ej. 124 de timeout)."""
    lines: list[str] = []
    shown = [0]

    def on_line(l: str) -> None:
        lines.append(l)
        if show and (not keep or shown[0] < keep):
            ctx.out.line(l)
            shown[0] += 1

    rc = system.stream(cmd, on_line, env=env, input=input, cwd=cwd)
    text = "\n".join(lines)
    if keep and len(lines) > keep:
        ctx.out.info(f"... {len(lines) - keep} líneas más" + (f" en {save_to}" if save_to else ""))
    if save_to:
        try:
            from .results import write
            write(save_to, text + "\n")
        except OSError:
            pass
    if rc == system.STOPPED or rc == -15:
        ctx.out.warn("Detenido por el usuario.")
    if accion:
        audit.record(accion, objetivo or "-", "OK" if rc in ok_rc else ("DETENIDO" if rc in (system.STOPPED, -15) else f"RC_{rc}"),
                     detalle)
    return rc, text


def check_params(action: Action, values: dict) -> Optional[str]:
    for p in action.visible_params():
        v = values.get(p.name, p.default)
        if p.kind == "choice" and p.choices and v in [c[0] for c in p.choices]:
            continue                       # una opción de la lista es válida aunque sea "" (p. ej. «Todas»)
        if p.required and p.kind != "bool" and (v is None or str(v).strip() == ""):
            return f"Falta: {p.label}"
        if p.kind == "int" and str(v).strip() and not str(v).strip().lstrip("-").isdigit():
            return f"{p.label}: debe ser un número"
        if p.kind == "choice" and p.choices:
            valid = [c[0] for c in p.choices]
            if v not in valid and not (v in ("", None) and not p.required):
                return f"{p.label}: opción no válida"
    return None


def execute(module: Module, action: Action, values: dict, ctx: Context) -> bool:
    """Punto único por el que pasan todas las acciones (interfaz y línea de comandos)."""
    for p in action.visible_params():
        values.setdefault(p.name, p.default)
        if isinstance(values[p.name], str):
            values[p.name] = values[p.name].strip() if p.kind != "password" else values[p.name]
    problem = check_params(action, values)
    if problem:
        ctx.out.error(problem)
        return False
    if action.changes and not system.is_root():
        ctx.out.error("Esta acción necesita root. Abre la herramienta con sudo.")
        return False
    if action.changes and audit.snapshot_accounts() == "ERROR":
        ctx.out.error("No se pudo hacer la copia previa de las cuentas (¿disco lleno?): no se aplica el cambio. "
                      "Libera espacio o desactiva [copias] cuentas en la configuración.")
        audit.record(f"{module.id}.{action.id}", "-", "CANCELADO", "sin copia previa de cuentas")
        return False
    try:
        return bool(action.run(ctx, values))
    except Exception as e:  # una acción con fallo no debe tumbar la herramienta
        ctx.out.error(f"Error inesperado en '{action.label}': {e}")
        audit.record(f"{module.id}.{action.id}", "-", "EXCEPCION", str(e))
        return False
