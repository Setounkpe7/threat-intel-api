from typer.testing import CliRunner

from threat_intel.cli.collect_once import app


def test_cli_help_lists_nvd_subcommand():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "nvd" in result.stdout


def test_cli_nvd_command_exists():
    """The 'nvd' subcommand must be invokable (we don't run it; just check it parses)."""
    result = CliRunner().invoke(app, ["nvd", "--help"])
    assert result.exit_code == 0
