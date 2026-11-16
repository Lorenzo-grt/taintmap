from importlib.metadata import version

from typer.testing import CliRunner

from taintmap.cli import app

runner = CliRunner()


def test_version_prints_package_metadata_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == version("taintmap")


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "version" in result.output
