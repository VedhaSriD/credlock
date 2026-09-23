"""
CredLock Formatter
Format and display scan results with colors and tables
"""

from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .scanner import Finding


console = Console()


class Formatter:
    """Format scan results for terminal output"""
    
    @staticmethod
    def print_scan_start(directory: str):
        """Print scan start message"""
        console.print(f"\n🔍 Scanning {directory} for secrets...\n", style="blue")
    
    @staticmethod
    def print_no_secrets():
        """Print when no secrets found"""
        console.print("✅ No secrets found. Scan clean!\n", style="green bold")
    
    @staticmethod
    def print_secrets_found(findings: List[Finding], scan_id: str = None):
        """
        Print secrets found with formatted output
        
        Args:
            findings: List of Finding objects
            scan_id: Scan ID for tracking
        """
        if not findings:
            Formatter.print_no_secrets()
            return False
        
        # Group findings by file
        by_file: Dict[str, List[Finding]] = {}
        for finding in findings:
            if finding.file not in by_file:
                by_file[finding.file] = []
            by_file[finding.file].append(finding)
        
        # Print header
        panel_text = f"⛔ SECRETS DETECTED! Found {len(findings)} potential secrets"
        console.print(Panel(panel_text, style="red bold"), end="\n")
        
        # Print by file
        for filepath, file_findings in sorted(by_file.items()):
            console.print(f"\n📄 [bold red]{filepath}[/bold red]", end="")
            console.print(f" ({len(file_findings)} secret{'s' if len(file_findings) > 1 else ''})\n")
            
            # Create table for this file
            table = Table(show_header=False, box=None, padding=(0, 2))
            
            for i, finding in enumerate(file_findings, 1):
                line_str = f"Line {finding.line_number}:"
                pattern_str = f"[{finding.pattern_name}]"
                
                table.add_row(
                    Text(line_str, style="yellow"),
                    Text(pattern_str, style="magenta"),
                    Text(finding.line_content[:60], style="dim")
                )
            
            console.print(table)
        
        # Print recommendations
        console.print("\n" + "="*60)
        console.print("[bold red]❌ PUSH BLOCKED[/bold red]")
        console.print("="*60 + "\n")
        
        console.print("[bold]Recommendations:[/bold]")
        console.print("1. Review each secret above")
        console.print("2. Move secrets to .env file (add to .gitignore)")
        console.print("3. Use environment variables in your code:")
        console.print("   const API_KEY = process.env.API_KEY;")
        console.print("4. Remove secrets from Git history:")
        console.print("   $ git rm --cached <file>")
        console.print("   $ git commit --amend")
        console.print("")
        
        if scan_id:
            console.print(f"Scan ID: {scan_id}", style="dim")
        
        console.print("")
        return True
    
    @staticmethod
    def print_dangerous_files(dangerous_files: List[str]):
        """Print dangerous files that exist"""
        if not dangerous_files:
            return
        
        console.print("\n[bold yellow]⚠️  DANGEROUS FILES DETECTED:[/bold yellow]\n")
        
        for filename in dangerous_files:
            console.print(f"  ❌ {filename}")
            console.print(f"     └─ This file should NEVER be committed!")
        
        console.print()
    
    @staticmethod
    def print_scan_summary(total_files: int, findings: List[Finding], duration: float):
        """Print scan summary"""
        console.print("\n" + "="*60)
        console.print("[bold]SCAN SUMMARY[/bold]")
        console.print("="*60)
        console.print(f"Files scanned: {total_files}")
        console.print(f"Secrets found: {len(findings)}")
        console.print(f"Duration: {duration:.3f} seconds")
        console.print("="*60 + "\n")
    
    @staticmethod
    def print_history(scans: List[Dict]):
        """Print scan history"""
        if not scans:
            console.print("No scan history found.\n")
            return
        
        console.print("\n[bold]📋 CREDLOCK SCAN HISTORY[/bold]\n")
        
        table = Table(title="Recent Scans")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Timestamp", style="yellow")
        table.add_column("Status", style="magenta")
        table.add_column("Secrets", justify="right")
        
        for scan in scans[:10]:  # Show last 10
            status = "✅ PASSED" if scan["secrets_found"] == 0 else f"❌ BLOCKED ({scan['secrets_found']})"
            table.add_row(
                scan["scan_id"],
                scan["timestamp"],
                status,
                str(scan["secrets_found"])
            )
        
        console.print(table)
        console.print()
    
    @staticmethod
    def print_config_info(config: Dict):
        """Print configuration information"""
        console.print("\n[bold]📝 CREDLOCK CONFIGURATION[/bold]\n")
        
        table = Table(show_header=False)
        table.add_column("Setting", style="cyan")
        table.add_column("Value")
        
        table.add_row("Patterns enabled", str(config.get("patterns_enabled", 50)))
        table.add_row("Custom patterns", str(config.get("custom_patterns", 0)))
        table.add_row("Config location", config.get("config_path", "~/.credlock/config.yaml"))
        
        console.print(table)
        console.print()
    
    @staticmethod
    def print_setup_success():
        """Print successful setup message"""
        console.print("\n" + "="*60)
        console.print("[bold green]✅ SETUP SUCCESSFUL[/bold green]")
        console.print("="*60)
        console.print("\nCredLock Git pre-commit hook installed!")
        console.print("\nFrom now on:")
        console.print("  • Secrets will be detected before you push")
        console.print("  • Dangerous files will be flagged")
        console.print("  • Scan history will be saved locally")
        console.print("\nTo verify:")
        console.print("  $ cat .git/hooks/pre-commit")
        console.print("\n" + "="*60 + "\n")
    
    @staticmethod
    def print_error(message: str):
        """Print error message"""
        console.print(f"\n[bold red]❌ ERROR:[/bold red] {message}\n")
    
    @staticmethod
    def print_success(message: str):
        """Print success message"""
        console.print(f"\n[bold green]✅ {message}[/bold green]\n")


# Create global formatter instance
_formatter = Formatter()


# Export functions
def print_scan_start(directory: str):
    return _formatter.print_scan_start(directory)


def print_no_secrets():
    return _formatter.print_no_secrets()


def print_secrets_found(findings: List[Finding], scan_id: str = None):
    return _formatter.print_secrets_found(findings, scan_id)


def print_dangerous_files(dangerous_files: List[str]):
    return _formatter.print_dangerous_files(dangerous_files)


def print_scan_summary(total_files: int, findings: List[Finding], duration: float):
    return _formatter.print_scan_summary(total_files, findings, duration)


def print_history(scans: List[Dict]):
    return _formatter.print_history(scans)


def print_config_info(config: Dict):
    return _formatter.print_config_info(config)


def print_setup_success():
    return _formatter.print_setup_success()


def print_error(message: str):
    return _formatter.print_error(message)


def print_success(message: str):
    return _formatter.print_success(message)