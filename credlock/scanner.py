"""
CredLock Scanner (FIXED)
Core logic for scanning files and detecting secrets
- Fixed custom patterns merging
- Fixed multiple secrets on same line detection
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Generator
from .patterns import PATTERNS, IGNORE_PATTERNS, SCAN_EXTENSIONS, DANGEROUS_FILES


@dataclass
class Finding:
    """Represents a detected secret"""
    file: str
    line_number: int
    pattern_name: str
    line_content: str
    matched_text: str = None
    
    def __str__(self):
        return f"{self.file}:{self.line_number} - {self.pattern_name}"


class Scanner:
    """File scanner for detecting secrets"""
    
    def __init__(self, custom_patterns=None):
        """
        Initialize scanner
        
        Args:
            custom_patterns: Dictionary of custom regex patterns
        """
        # FIXED: Properly merge custom patterns with built-in patterns
        self.patterns = PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)
    
    def should_ignore_file(self, filepath: str) -> bool:
        """Check if file should be ignored"""
        for ignore_pattern in IGNORE_PATTERNS:
            if re.search(ignore_pattern, filepath):
                return True
        return False
    
    def should_scan_file(self, filepath: str) -> bool:
        """Check if file should be scanned based on extension"""
        _, ext = os.path.splitext(filepath)
        return ext in SCAN_EXTENSIONS or filepath.endswith(tuple(DANGEROUS_FILES))
    
    def scan_file(self, filepath: str) -> List[Finding]:
        """
        Scan a single file for secrets
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    for pattern_name, regex_pattern in self.patterns.items():
                        # FIXED: Use finditer to find ALL matches on the line, not just first
                        matches = re.finditer(regex_pattern, line)
                        for match in matches:
                            finding = Finding(
                                file=filepath,
                                line_number=line_number,
                                pattern_name=pattern_name,
                                line_content=line.rstrip(),
                                matched_text=match.group(0)[:50]  # First 50 chars
                            )
                            findings.append(finding)
        except Exception as e:
            # Skip files that can't be read
            pass
        
        return findings
    
    def scan_directory(self, directory: str = ".") -> List[Finding]:
        """
        Scan entire directory recursively
        
        Args:
            directory: Directory to scan (default: current directory)
            
        Returns:
            List of all Finding objects
        """
        all_findings = []
        
        for filepath in Path(directory).rglob("*"):
            if not filepath.is_file():
                continue
            
            filepath_str = str(filepath)
            
            # Skip ignored files
            if self.should_ignore_file(filepath_str):
                continue
            
            # Only scan certain file types
            if not self.should_scan_file(filepath_str):
                continue
            
            findings = self.scan_file(filepath_str)
            all_findings.extend(findings)
        
        return all_findings
    
    def scan_content(self, content: str) -> List[Finding]:
        """
        Scan string content for secrets
        
        Args:
            content: String content to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        for line_number, line in enumerate(content.split('\n'), 1):
            for pattern_name, regex_pattern in self.patterns.items():
                # FIXED: Use finditer to find ALL matches on the line
                matches = re.finditer(regex_pattern, line)
                for match in matches:
                    finding = Finding(
                        file="<content>",
                        line_number=line_number,
                        pattern_name=pattern_name,
                        line_content=line.rstrip(),
                        matched_text=match.group(0)[:50]
                    )
                    findings.append(finding)
        
        return findings
    
    def check_dangerous_files(self, directory: str = ".") -> List[str]:
        """
        Check for dangerous files that should never be committed
        
        Args:
            directory: Directory to check
            
        Returns:
            List of dangerous files found
        """
        found_dangerous = []
        
        for dangerous_file in DANGEROUS_FILES:
            filepath = Path(directory) / dangerous_file
            if filepath.exists():
                found_dangerous.append(str(filepath))
        
        return found_dangerous


# Create global scanner instance
_scanner = Scanner()


def scan_file(filepath: str) -> List[Finding]:
    """Scan a single file"""
    return _scanner.scan_file(filepath)


def scan_directory(directory: str = ".") -> List[Finding]:
    """Scan entire directory"""
    return _scanner.scan_directory(directory)


def scan_content(content: str) -> List[Finding]:
    """Scan string content"""
    return _scanner.scan_content(content)


def check_dangerous_files(directory: str = ".") -> List[str]:
    """Check for dangerous files"""
    return _scanner.check_dangerous_files(directory)