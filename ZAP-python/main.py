import typer
import sys
import os
from pathlib import Path

# Add the project root to sys.path to ensure imports work correctly
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from rich.console import Console
from rich.table import Table

app = typer.Typer(help="ZAP-Python: A lightweight OWASP API Security Scanner (CLI)")
console = Console()

@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target Base URL (e.g., http://localhost:8888)"),
    spec: str = typer.Option(..., "--spec", "-s", help="Path to OpenAPI Spec file (json/yaml)"),
    token: str = typer.Option(None, "--token", help="Bearer Token for authentication"),
    output: str = typer.Option("report", "--output", "-o", help="Base output filename (without extension)"),
    format: str = typer.Option("all", "--format", help="Report format: json, md, or all"),
    full: bool = typer.Option(False, "--full", "-f", help="Run all available scanners including slow ones")
):
    """
    Start an API Security Scan against a target.
    """
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    console.print(f"[bold green]Starting ZAP-Python Scan[/bold green]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Spec: [cyan]{spec}[/cyan]")
    
    # 1. Initialize Context
    from core.context import ScanContext, AuthConfig
    from core.engine import AttackEngine
    import json
    import json
    
    auth_config = AuthConfig(token=token) if token else AuthConfig()
    context = ScanContext(target_url=target, auth=auth_config)
    
    # 2. Initialize Engine
    engine = AttackEngine(context)
    
    # 3. Load Scanners
    # Dynamic loading is now handled by the engine
    engine.load_scanners()
    
    # 4. Start Scan
    try:
        results = engine.start_scan(spec_path=spec)
    except Exception as e:
        console.print(f"[bold red]Scan Failed: {e}[/bold red]")
        return
    
    # 5. Generate Reports
    report = engine.generate_report()
    
    if format.lower() in ["json", "all"]:
        json_file = f"{output}.json"
        with open(json_file, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green]JSON Report saved: {json_file}[/green]")

    if format.lower() in ["md", "markdown", "all"]:
        md_file = f"{output}.md"
        engine.save_markdown_report(md_file)
        console.print(f"[green]Markdown Report saved: {md_file}[/green]")
        
    console.print(f"[bold green]Scan Complete! Report saved to {output} and report.md[/bold green]")
    console.print(f"Total Findings: {len(report['findings'])}")

@app.command()
def list_rules():
    """
    List all available vulnerability scanners/plugins.
    """
    table = Table(title="Available Scanners")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("OWASP API Category")
    
    from core.context import ScanContext
    from core.engine import AttackEngine

    # Initialize dummy context for loading scanners
    context = ScanContext(target_url="http://localhost")
    engine = AttackEngine(context)
    
    # Load scanners dynamically
    try:
        engine.load_scanners()
    except Exception as e:
        console.print(f"[bold red]Error loading scanners: {e}[/bold red]")
        return

    for scanner in engine.scanners:
        table.add_row(scanner.scan_id, scanner.name, scanner.category)

    console.print(table)

if __name__ == "__main__":
    app()
