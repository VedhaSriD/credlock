"""
CredLock CLI
Command-line interface for CredLock
"""

import typer
import time
import os
from pathlib import Path
from typing import Optional
from .scanner import scan_directory, scan_file, check_dangerous_files
from .formatter import (
    print_scan_start, print_no_secrets, print_secrets_found,
    print_dangerous_files, print_scan_summary, print_history,
    print_config_info, print_setup_success, print_error, print_success
)
from .storage import save_scan, get_history, get_storage_path
from .config import load_config, add_custom_pattern
from . import __version__


app = typer.Typer(
    name="credlock",
    help="🔐 Prevent accidental credential commits to Git"
)


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan"),
    exit_on_secrets: bool = typer.Option(True, help="Exit with code 1 if secrets found")
):
    """
    Scan directory for secrets
    
    Usage:
        credlock scan              # Scan current directory
        credlock scan /path/to/dir # Scan specific directory
    """
    print_scan_start(directory)
    
    start_time = time.time()
    
    # Scan directory
    findings = scan_directory(directory)
    
    # Check for dangerous files
    dangerous_files = check_dangerous_files(directory)
    
    # Count total files scanned
    total_files = sum(1 for p in Path(directory).rglob("*") if p.is_file())
    
    duration = time.time() - start_time
    
    # Save scan to history
    scan_data = {
        "directory": directory,
        "secrets_found": len(findings),
        "dangerous_files": len(dangerous_files),
        "total_files": total_files,
        "duration": duration,
        "findings": [
            {
                "file": f.file,
                "line": f.line_number,
                "pattern": f.pattern_name,
                "content": f.line_content[:100]
            } for f in findings
        ]
    }
    scan_id = save_scan(scan_data)
    
    # Print results
    if findings:
        print_secrets_found(findings, scan_id)
        if dangerous_files:
            print_dangerous_files(dangerous_files)
    else:
        print_no_secrets()
    
    # Print dangerous files if found
    if dangerous_files:
        print_dangerous_files(dangerous_files)
    
    print_scan_summary(total_files, findings, duration)
    
    # Exit with appropriate code
    if exit_on_secrets and (findings or dangerous_files):
        raise typer.Exit(code=1)
    
    raise typer.Exit(code=0)


@app.command()
def setup_git():
    """
    Install Git pre-commit hook
    
    This command installs a pre-commit hook that runs CredLock
    automatically before every git push.
    """
    git_dir = Path(".git")
    if not git_dir.exists():
        print_error("Not a git repository. Run 'git init' first.")
        raise typer.Exit(code=1)
    
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    
    pre_commit_path = hooks_dir / "pre-commit"
    
    # Create pre-commit hook script
    hook_script = """#!/bin/bash
# CredLock - Automatic Secret Detection
# This hook prevents accidental secret commits

credlock scan

if [ $? -ne 0 ]; then
    echo ""
    echo "[CredLock] Secrets detected. Push blocked."
    echo "Fix the issues above before trying again."
    exit 1
fi

exit 0
"""
    
    # Write hook file
    with open(pre_commit_path, 'w') as f:
        f.write(hook_script)
    
    # Make executable
    os.chmod(pre_commit_path, 0o755)
    
    print_setup_success()


@app.command()
def history(
    limit: int = typer.Option(10, help="Number of scans to show")
):
    """
    View scan history
    
    Usage:
        credlock history           # Show last 10 scans
        credlock history --limit=5 # Show last 5 scans
    """
    scans = get_history(limit)
    
    if not scans:
        print_error("No scan history found")
        raise typer.Exit(code=0)
    
    # Format scans for display
    formatted_scans = []
    for scan in scans:
        formatted_scans.append({
            "scan_id": scan.get("scan_id", "unknown"),
            "timestamp": scan.get("timestamp", "unknown")[:19],
            "secrets_found": scan.get("secrets_found", 0),
            "dangerous_files": scan.get("dangerous_files", 0),
            "duration": f"{scan.get('duration', 0):.3f}s"
        })
    
    print_history(formatted_scans)


@app.command()
def configure():
    """
    Configure CredLock settings
    
    Interactive configuration wizard
    """
    config = load_config()
    
    print_config_info(config)
    
    typer.echo("\nWhat would you like to do?")
    typer.echo("1. Add custom pattern")
    typer.echo("2. View all patterns")
    typer.echo("3. Reset to defaults")
    typer.echo("4. Exit")
    
    choice = typer.prompt("Enter your choice (1-4)", type=int)
    
    if choice == 1:
        name = typer.prompt("Pattern name")
        regex = typer.prompt("Regex pattern")
        add_custom_pattern(name, regex)
        print_success(f"Custom pattern '{name}' added!")
    
    elif choice == 2:
        typer.echo("\nBuilt-in patterns: 50+")
        typer.echo("Custom patterns: " + str(len(config.get("custom_patterns", {}))))
    
    elif choice == 3:
        from .config import _config
        _config.save(_config.get_default_config())
        print_success("Configuration reset to defaults")
    
    else:
        typer.echo("Exiting...")
        raise typer.Exit(code=0)


@app.command()
def version():
    """
    Show version information
    """
    typer.echo(f"CredLock v{__version__}")
    typer.echo("🔐 Prevent accidental credential commits to Git")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    show_version: bool = typer.Option(False, "--version", help="Show version"),
):
    """
    CredLock - Automatic credential detection in your code
    
    Prevent accidental secret commits to Git with automatic pre-commit scanning.
    
    Usage:
        credlock scan              Scan current directory
        credlock setup-git         Install Git pre-commit hook
        credlock history           View scan history
        credlock configure         Configure settings
    """
    if show_version:
        typer.echo(f"CredLock v{__version__}")
        raise typer.Exit(code=0)
    
    # If no command provided, show help
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()