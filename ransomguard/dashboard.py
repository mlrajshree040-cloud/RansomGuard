from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def banner():
    console.print(Panel.fit(
        "[bold cyan]🛡️  RansomGuard[/bold cyan]\n"
        "[white]Ransomware Detection & Deception System[/white]",
        border_style="cyan"
    ))


def show_decoy_status(count):
    console.print(f"[yellow]🍯 Decoy files deployed:[/yellow] [bold]{count}[/bold]")


def show_threat(threat):
    table = Table(title="🚨 THREAT DETECTED", border_style="red")
    table.add_column("Field", style="red")
    table.add_column("Value", style="white")
    table.add_row("Severity", str(threat["severity"]))
    table.add_row("Reasons", "\n".join(threat["reasons"]))
    table.add_row("Affected files", str(len(threat["paths"])))
    console.print(table)


def show_containment(killed, locked, snapshot):
    console.print(Panel.fit(
        f"[bold green]✅ Attack Contained[/bold green]\n"
        f"Processes killed: [red]{len(killed)}[/red]\n"
        f"Files unlocked: [yellow]{locked}[/yellow]\n"
        f"Snapshot: [cyan]{snapshot}[/cyan]",
        border_style="green"
    ))


def show_info(msg):
    console.print(f"[blue]ℹ[/blue] {msg}")


def show_warn(msg):
    console.print(f"[yellow]⚠[/yellow] {msg}")