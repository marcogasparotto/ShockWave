"""Shockwave - Ponto de entrada para python -m shockwave."""

import sys

from shockwave.app import ShockwaveApp
from shockwave import ui


def main():
    """Ponto de entrada principal."""
    if len(sys.argv) < 2:
        ui.console.print()
        ui.print_error("Nenhum alvo especificado!")
        ui.console.print()
        ui.console.print("  [bold magenta]Uso:[/bold magenta]")
        ui.console.print("    python -m shockwave [bold cyan]<alvo>[/bold cyan]")
        ui.console.print()
        ui.console.print("  [bold magenta]Exemplos:[/bold magenta]")
        ui.console.print("    python -m shockwave [cyan]google.com[/cyan]")
        ui.console.print("    python -m shockwave [cyan]192.168.1.1[/cyan]")
        ui.console.print("    python -m shockwave [cyan]example.org[/cyan]")
        ui.console.print()
        sys.exit(1)

    target = sys.argv[1]
    app = ShockwaveApp(target)
    app.run()


if __name__ == "__main__":
    main()