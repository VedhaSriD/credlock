"""
Terminal output formatting for CredLock
"""

from rich.console import Console
from typing import List, Dict
from collections import defaultdict
from credlock.scanner import Finding

console = Console()


def print_scan_start():
    """Print scan start message"""
    console.print("[cyan]🔍 Scanning current directory...[/cyan]")


def print_no_secrets():
    """Print success message when no secrets found"""
    console.print("[green]✅ No secrets found. Scan clean![/green]")


def print_secrets_found(findings: List[Finding], verbose: bool = False):
    """
    Print findings grouped by file (NOT as table)
    
    Args:
        findings: List of Finding objects
        verbose: Show detailed output (not used, but kept for compatibility)
    """
    if not findings:
        print_no_secrets()
        return
    
    # Group findings by file
    by_file = defaultdict(list)
    for finding in findings:
        by_file[finding.file_path].append(finding)
    
    # Print header
    console.print("\n[red]⛔ SECRETS DETECTED! Found {} potential secrets[/red]".format(len(findings)))
    console.print()
    
    # Print grouped by file
    for file_path in sorted(by_file.keys()):
        file_findings = by_file[file_path]
        console.print(f"[cyan]📄 {file_path}[/cyan] [yellow]({len(file_findings)} secret{'s' if len(file_findings) > 1 else ''})[/yellow]")
        
        for finding in file_findings:
            # Extract just the pattern name (without "pattern_" prefix if present)
            pattern_display = finding.pattern_name
            
            # Truncate matched string to 40 chars for display
            matched_display = finding.matched_string[:40]
            if len(finding.matched_string) > 40:
                matched_display += "..."
            
            console.print(
                f"  [yellow]Line {finding.line_number}:[/yellow] "
                f"[magenta][{pattern_display}][/magenta] "
                f"{matched_display}"
            )
        
        console.print()


def print_dangerous_files(files: List[str]):
    """Print dangerous files found"""
    if not files:
        return
    
    console.print("\n[red]⚠️ Dangerous Files Found:[/red]")
    for file in files:
        console.print(f"  [red]•[/red] {file}")


def print_scan_summary(findings_count: int, duration: float, files_scanned: int = 0):
    """Print scan summary"""
    if findings_count > 0:
        console.print("[red]❌ PUSH BLOCKED - {} SECRET{} FOUND[/red]".format(
            findings_count,
            'S' if findings_count > 1 else ''
        ))
        console.print()
        console.print("[cyan]Recommendations:[/cyan]")
        console.print("1. Move secrets to .env file")
        console.print("2. Add .env to .gitignore")
        console.print("3. Use environment variables in code")
        console.print()
        console.print("[yellow]Git commands to fix:[/yellow]")
        console.print("  $ echo '.env' >> .gitignore")
        console.print("  $ git rm --cached .env")
        console.print("  $ git commit --amend")
    else:
        console.print("[green]✅ SCAN PASSED - Safe to push![/green]")
    
    console.print(f"\n[cyan]Scan Summary:[/cyan]")
    console.print(f"  Files scanned: {files_scanned}")
    console.print(f"  Secrets found: {findings_count}")
    console.print(f"  Duration: {duration:.2f}s")


def print_history(scans: List[Dict]):
    """Print scan history"""
    if not scans:
        console.print("[yellow]No scan history found[/yellow]")
        return
    
    console.print("[cyan]Scan History:[/cyan]")
    for i, scan in enumerate(scans, 1):
        ts = scan.get("timestamp", "")[:10]
        count = scan.get("findings_count", 0)
        console.print(f"  {i}. {ts} - {count} findings")


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
    
    # Group by file
    by_file = defaultdict(list)
    for finding in findings:
        by_file[finding.file_path].append(finding)
    
    output = f"\n⛔ SECRETS DETECTED! Found {len(findings)} potential secret(s)\n"
    
    for file_path in sorted(by_file.keys()):
        file_findings = by_file[file_path]
        output += f"\n📄 {file_path} ({len(file_findings)} secret{'s' if len(file_findings) > 1 else ''})\n"
        
        for finding in file_findings:
            matched_display = finding.matched_string[:40]
            if len(finding.matched_string) > 40:
                matched_display += "..."
            
            output += f"  Line {finding.line_number}: [{finding.pattern_name}] {matched_display}\n"
    
    return output