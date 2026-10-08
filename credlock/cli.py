"""
Command-line interface for CredLock.
"""

import time
import typer
import json
from pathlib import Path
from typing import Optional
from rich.console import Console

from . import __version__
from .scanner import scan_directory, scan_file
from .formatter import print_scan_start, print_no_secrets, print_secrets_found, print_scan_summary
from .storage import save_scan, get_history
from .git_hook import setup_hook, is_in_git_repo
from .config import load_config, save_config

app = typer.Typer(help="🔒 CredLock - Prevent accidental credential commits")
console = Console()


def count_files_in_directory(path: str) -> int:
    """Count total files in directory"""
    try:
        return len(list(Path(path).rglob("*")))
    except:
        return 0


@app.command()
def scan(
    path: str = typer.Argument("."),
    staged: bool = typer.Option(False, "--staged", help="Scan only staged files"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Scan for secrets"""
    console = Console()
    start_time = time.time()
    
    # Print start message
    console.print(f"🔍 Scanning {path} for secrets...")
    print_scan_start()
    
    # Count files
    files_scanned = count_files_in_directory(path)
    
    # Scan directory
    if staged:
        # For staged files, we'd need git integration
        findings = scan_directory(path)
    else:
        findings = scan_directory(path)
    
    elapsed = time.time() - start_time
    
    # Display results
    if not findings:
        print_no_secrets()
    else:
        print_secrets_found(findings)
    
    # Print summary
    print_scan_summary(len(findings), elapsed, files_scanned)
    
    # Save to history
    save_scan(len(findings), path)
    
    # JSON output if requested
    if json_output:
        output = {
            "path": path,
            "findings_count": len(findings),
            "files_scanned": files_scanned,
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "pattern_name": f.pattern_name,
                    "confidence": f.confidence,
                    "matched_string": f.matched_string[:50] + "..." if len(f.matched_string) > 50 else f.matched_string,
                }
                for f in findings
            ],
            "elapsed_seconds": elapsed,
        }
        console.print(json.dumps(output, indent=2))
    
    # Exit with code 1 if secrets found (for git hook)
    if findings:
        raise typer.Exit(code=1)


@app.command()
def history(limit: int = typer.Option(10, "--limit", "-l")):
    """View scan history."""
    scans = get_history(limit)
    if not scans:
        console.print("[yellow]No history[/yellow]")
    else:
        for i, scan in enumerate(scans, 1):
            ts = scan.get("timestamp", "")[:10]
            count = scan.get("findings_count", 0)
            console.print(f"{i}. {ts} - {count} findings")


@app.command()
def configure():
    """Configure CredLock."""
    try:
        config = load_config()
        
        while True:
            console.print("\n[cyan]CredLock Config[/cyan]")
            console.print("1. View")
            console.print("2. Edit")
            console.print("3. Reset")
            console.print("4. Exit")
            
            choice = input("Choice (1-4): ")
            
            if choice == "1":
                console.print(f"Storage: {config.get('storage_dir')}")
            elif choice == "2":
                key = input("Key: ")
                value = input("Value: ")
                config[key] = value
                save_config(config)
                console.print("[green]✅ Saved[/green]")
            elif choice == "3":
                from .config import DEFAULT_CONFIG
                save_config(DEFAULT_CONFIG)
                console.print("[green]✅ Reset[/green]")
            elif choice == "4":
                break
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def setup(force: bool = typer.Option(False, "--force", "-f", help="Force reinstall")):
    """Setup git hook."""
    try:
        if not is_in_git_repo():
            console.print("[red]Not in git repo[/red]")
            raise typer.Exit(code=1)
        
        setup_hook(force=force)
        console.print("[green]✅ Git hook installed![/green]")
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Show version."""
    console.print(f"[cyan]CredLock {__version__}[/cyan]")


if __name__ == "__main__":
    app()