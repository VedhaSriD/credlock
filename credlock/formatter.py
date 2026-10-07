"""
Terminal output formatting for CredLock
"""

from rich.console import Console
from rich.table import Table
from typing import List, Dict
from credlock.scanner import Finding

console = Console()


def print_scan_start():
    """Print scan start message"""
    console.print("[cyan]🔍 Scanning for secrets...[/cyan]")


def print_no_secrets():
    """Print success message when no secrets found"""
    console.print("[green]✅ No secrets found. Scan clean![/green]")


def print_secrets_found(findings: List[Finding], verbose: bool = False):
    """
    Print findings in formatted table
    
    Args:
        findings: List of Finding objects
        verbose: Show detailed output
    """
    console.print("\n[red]⛔ SECRETS DETECTED![/red]")
    console.print(f"[red]Found {len(findings)} potential secret(s)[/red]\n")
    
    # Create table
    table = Table(title="Secret Findings")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="yellow")
    table.add_column("Pattern", style="magenta")
    table.add_column("Confidence", style="red")
    
    for finding in findings:
        table.add_row(
            finding.file_path,
            str(finding.line_number),
            finding.pattern_name,
            finding.confidence
        )
    
    console.print(table)
    
    # Show details if verbose
    if verbose:
        console.print("\n[bold]Detailed Output:[/bold]")
        for finding in findings:
            console.print(f"\n[yellow]File:[/yellow] {finding.file_path}")
            console.print(f"[yellow]Line {finding.line_number}:[/yellow] {finding.line_content}")
            console.print(f"[yellow]Pattern:[/yellow] {finding.pattern_name}")
            console.print(f"[yellow]Confidence:[/yellow] {finding.confidence}")
            console.print(f"[yellow]Entropy:[/yellow] {finding.entropy:.2f}")


def print_dangerous_files(files: List[str]):
    """Print dangerous files found"""
    if not files:
        return
    
    console.print("\n[red]⚠️ Dangerous Files Found:[/red]")
    for file in files:
        console.print(f"  [red]•[/red] {file}")


def print_scan_summary(findings_count: int, duration: float, files_scanned: int = 0):
    """Print scan summary"""
    console.print(f"\n[cyan]Scan Summary:[/cyan]")
    console.print(f"  Files scanned: {files_scanned}")
    console.print(f"  Secrets found: {findings_count}")
    console.print(f"  Duration: {duration:.2f}s")


def print_history(scans: List[Dict]):
    """Print scan history"""
    if not scans:
        console.print("[yellow]No scan history found[/yellow]")
        return
    
    table = Table(title="Scan History")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Timestamp", style="yellow")
    table.add_column("Secrets Found", style="red")
    table.add_column("Duration", style="green")
    
    for scan in scans:
        table.add_row(
            scan.get("scan_id", "unknown"),
            scan.get("timestamp", "unknown"),
            str(scan.get("secrets_found", 0)),
            scan.get("duration", "0s")
        )
    
    console.print(table)


def print_config_info(config: Dict):
    """Print configuration information"""
    console.print("[cyan]Current Configuration:[/cyan]")
    console.print(f"  Built-in patterns: 50+")
    console.print(f"  Custom patterns: {len(config.get('custom_patterns', {}))}")
    console.print(f"  Ignored files: {len(config.get('ignored_files', []))}")


def print_setup_success():
    """Print setup success message"""
    console.print("\n[green]✅ Git pre-commit hook installed successfully![/green]")
    console.print("[cyan]The hook will now run automatically before each commit.[/cyan]")


def print_error(message: str):
    """Print error message"""
    console.print(f"[red]❌ ERROR: {message}[/red]")


def print_success(message: str):
    """Print success message"""
    console.print(f"[green]✅ {message}[/green]")


def format_findings(findings: List[Finding], verbose: bool = False) -> str:
    """
    Format findings as string (alternative to print_secrets_found)
    
    Args:
        findings: List of Finding objects
        verbose: Show detailed output
        
    Returns:
        Formatted string
    """
    if not findings:
        return "No secrets found."
    
    output = f"\n⛔ SECRETS DETECTED! Found {len(findings)} potential secret(s)\n"
    
    for finding in findings:
        output += f"\n📄 {finding.file_path} (Line {finding.line_number})\n"
        output += f"  Pattern: {finding.pattern_name}\n"
        output += f"  Confidence: {finding.confidence}\n"
        
        if verbose:
            output += f"  Content: {finding.line_content}\n"
            output += f"  Entropy: {finding.entropy:.2f}\n"
    
    return output