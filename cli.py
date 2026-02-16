import argparse
import asyncio
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box

from app.utils.formatters import normalize_url
from app.core.scanner import APIScanner
from app.core.analyzer import RiskAnalyzer

console = Console()

def print_banner():
    banner_text = r"""
    _    ____  ___    ____                     _ 
   / \  |  _ \|_ _|  / ___|_   _  __ _ _ __ __| |
  / _ \ | |_) || |  | |  _| | | |/ _` | '__/ _` |
 / ___ \|  __/ | |  | |_| | |_| | (_| | | | (_| |
/_/   \_\_|   |___|  \____|\__,_|\__,_|_|  \__,_|
                                         v 2 . 0
    """
    console.print(Text(banner_text, style="bold cyan"))
    console.print(Align.center("[dim]Defensive Security Assessment Tool[/dim]"))
    console.print(Align.center("[red]DISCLAIMER: Use only for defensive auditing on your own assets.[/red]\n"))

def print_usage():
    print_banner()
    usage_panel = Panel(
        """
[bold yellow]Kullanım:[/bold yellow]
  python cli.py [bold cyan]<HEDEF>[/bold cyan] [seçenekler]

[bold yellow]Seçenekler:[/bold yellow]
  --json       Çıktıyı saf JSON formatında verir (CI/CD için).

[bold yellow]Örnekler:[/bold yellow]
  python cli.py google.com
  python cli.py api.startup.com --json
        """,
        title="[bold red]Usage Guide[/bold red]",
        border_style="red",
        expand=False
    )
    console.print(usage_panel)

async def main(target_url: str, json_mode: bool):
    normalized_target = normalize_url(target_url)
    
    if not json_mode:
        print_banner()
        console.print(f"[bold]Target locked:[/bold] [cyan]{normalized_target}[/cyan]")

    scanner = APIScanner(normalized_target)
    
    if json_mode:
        results = await scanner.scan()
    else:
        with console.status("[bold cyan]Running defensive checks (SSL, Headers, RateLimit)...", spinner="bouncingBall"):
            results = await scanner.scan()

    # Analiz
    analyzer = RiskAnalyzer(results)
    score, findings = analyzer.analyze()

    # --- JSON ÇIKTISI (CI/CD) ---
    if json_mode:
        output = {
            "target": normalized_target,
            "score": score,
            "scan_time": str(results.get("scan_time", "")),
            "findings": [
                {
                    "category": f.category,
                    "risk": f.risk,
                    "status": f.status,
                    "details": f.details
                } for f in findings
            ]
        }
        print(json.dumps(output, indent=2))
        return

    # --- RICH UI ÇIKTISI ---
    if results.get("status") != "up":
        console.print(f"[bold red]HATA:[/bold red] {normalized_target} hedefine ulaşılamadı.")
        return

    table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_lines=True)
    table.add_column("KONTROL", style="cyan", no_wrap=True)
    table.add_column("DURUM", justify="center")
    table.add_column("RİSK", justify="center")
    table.add_column("DETAYLAR", style="white")

    risk_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "SAFE": "bold green",
        "INFO": "dim white"
    }

    status_icons = {
        "PASS": "[green]✔[/green]",
        "FAIL": "[red]✖[/red]",
        "WARN": "[yellow]![/yellow]",
        "INFO": "[blue]i[/blue]"
    }

    failed_checks = []

    for f in findings:
        r_style = risk_styles.get(f.risk, "white")
        table.add_row(
            f.category,
            status_icons.get(f.status, f.status),
            f"[{r_style}]{f.risk}[/{r_style}]",
            f.details
        )
        if f.status in ["FAIL", "WARN"]:
            failed_checks.append(f)

    console.print(table)
    console.print()

    # Skor Paneli
    score_color = "red"
    if score >= 80: score_color = "green"
    elif score >= 50: score_color = "yellow"
    
    score_panel = Panel(
        Align.center(f"[bold {score_color} extra_large]{score}[/bold {score_color} extra_large]\n[dim]Security Score[/dim]"),
        title="[bold]AUDIT RESULT[/bold]",
        border_style=score_color,
        width=40
    )
    console.print(Align.center(score_panel))
    console.print()

    if failed_checks:
        console.print("[bold underline]Aksiyon Planı:[/bold underline]")
        for i, f in enumerate(failed_checks, 1):
            console.print(f"{i}. [bold cyan]{f.category}:[/bold cyan] {f.hint}")
    else:
        console.print("[bold green]Sistem temiz görünüyor. İyi iş![/bold green]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APIGuard Lite v2.0", add_help=False)
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("--json", action="store_true", help="Output results in JSON")
    
    args = parser.parse_args()

    if not args.target:
        print_usage()
        sys.exit(1)

    try:
        asyncio.run(main(args.target, args.json))
    except KeyboardInterrupt:
        sys.exit(0)