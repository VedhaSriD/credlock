"""
Scan files and directories for secrets.
"""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional
import subprocess

from .patterns import PATTERNS, SecretPattern
from .entropy import is_likely_secret, calculate_entropy
from .gitignore_parser import should_ignore_by_default, GitignoreParser


@dataclass
class Finding:
    """A secret finding."""
    file_path: str
    line_number: int
    line_content: str
    pattern_name: str
    matched_string: str
    confidence: str
    entropy: float


class Scanner:
    """Scan content and files for secrets."""
    
    def __init__(self, custom_patterns: Dict[str, str] = None):
        """
        Initialize scanner.
        
        Args:
            custom_patterns: Dict of {name: regex_pattern} to add to built-in patterns
        """
        # Copy built-in patterns
        self.patterns = dict(PATTERNS)
        
        # Add custom patterns - FIX: Convert string regex to SecretPattern
        if custom_patterns:
            for name, regex_pattern in custom_patterns.items():
                self.patterns[name] = SecretPattern(
                    name=name,
                    pattern=regex_pattern,
                    confidence="MEDIUM",
                    entropy_threshold=3.0,
                    exclude_files=[]
                )
        
        self.gitignore_parser = None
    
    def scan_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
        include_low_confidence: bool = False
    ) -> List[Finding]:
        """
        Scan a single line for secrets.
        
        Args:
            line: Line content
            line_number: Line number
            file_path: File path (for reporting)
            include_low_confidence: Include LOW confidence findings
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Try each pattern
        for pattern_name, pattern_obj in self.patterns.items():
            # Handle both SecretPattern objects and old string patterns
            if isinstance(pattern_obj, str):
                # Old format - skip
                continue
            
            # Check confidence level
            if pattern_obj.confidence == "LOW" and not include_low_confidence:
                continue
            
            # Get regex pattern
            regex = pattern_obj.pattern
            
            # Find all matches
            try:
                for match in re.finditer(regex, line, re.IGNORECASE):
                    matched_str = match.group(0)
                    
                    # FILTER: Natural language messages for password_assignment
                    if pattern_name == "password_assignment":
                        if any(word in matched_str.lower() for word in 
                               ["must", "error", "please", "enter", "confirm", 
                                "match", "invalid", "required", "minimum", "character"]):
                            continue
                    
                    # Calculate entropy
                    entropy = calculate_entropy(matched_str)
                    
                    # Check if likely a real secret (entropy threshold)
                    if not is_likely_secret(matched_str, pattern_name):
                        continue
                    
                    # Create finding
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_number,
                        line_content=line,
                        pattern_name=pattern_name,
                        matched_string=matched_str,
                        confidence=pattern_obj.confidence,
                        entropy=entropy
                    )
                    
                    findings.append(finding)
            
            except Exception as e:
                # Regex error - skip pattern
                continue
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a file for secrets.
        
        Args:
            file_path: Path to file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.rstrip('\n\r')
                    line_findings = self.scan_line(line, line_num, file_path)
                    findings.extend(line_findings)
        
        except Exception as e:
            # File read error
            pass
        
        return findings
    
    def scan_directory(
        self,
        directory: str,
        staged_only: bool = False,
        include_low_confidence: bool = False
    ) -> List[Finding]:
        """
        Scan a directory for secrets.
        
        Args:
            directory: Directory path
            staged_only: Only scan git staged files
            include_low_confidence: Include LOW confidence findings
            
        Returns:
            List of Finding objects
        """
        findings = []
        dir_path = Path(directory)
        
        # Get staged files if requested
        staged_files = set()
        if staged_only:
            try:
                result = subprocess.run(
                    ["git", "diff", "--cached", "--name-only"],
                    cwd=directory,
                    capture_output=True,
                    text=True
                )
                staged_files = set(result.stdout.strip().split('\n'))
                staged_files.discard('')
            except Exception:
                pass
        
        # Scan files
        for file_path in dir_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip ignored files
            if should_ignore_by_default(file_path):
                continue
            
            # Skip non-staged if requested
            if staged_only:
                rel_path = str(file_path.relative_to(dir_path)).replace('\\', '/')
                if rel_path not in staged_files:
                    continue
            
            # Scan file
            try:
                file_findings = self.scan_file(str(file_path))
                
                # Filter by confidence
                for finding in file_findings:
                    if finding.confidence == "LOW" and not include_low_confidence:
                        continue
                    findings.append(finding)
            
            except Exception:
                pass
        
        return findings


# Global scanner instance
_scanner = Scanner()


def scan_content(content: str) -> List[Finding]:
    """
    Scan content string for secrets.
    
    Args:
        content: Content to scan
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    for line_num, line in enumerate(content.split('\n'), 1):
        line_findings = _scanner.scan_line(line, line_num, "content")
        findings.extend(line_findings)
    
    return findings


def scan_file(file_path: str) -> List[Finding]:
    """
    Scan a file for secrets.
    
    Args:
        file_path: Path to file
        
    Returns:
        List of Finding objects
    """
    return _scanner.scan_file(file_path)


def scan_directory(directory: str, staged_only: bool = False) -> List[Finding]:
    """
    Scan a directory for secrets.
    
    Args:
        directory: Directory path
        staged_only: Only scan git staged files
        
    Returns:
        List of Finding objects
    """
    return _scanner.scan_directory(directory, staged_only=staged_only)