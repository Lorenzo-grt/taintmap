"""Command-line interface."""

from importlib.metadata import version as _dist_version

import typer

app = typer.Typer(
    name="taintmap",
    help="Map how untrusted input flows through AI agents, automations and code.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """Map how untrusted input flows through AI agents, automations and code."""


@app.command()
def version() -> None:
    """Print the installed taintmap version."""
    typer.echo(_dist_version("taintmap"))
