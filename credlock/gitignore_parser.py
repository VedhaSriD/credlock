"""
Parse and respect .gitignore files.

Prevents scanning files that are already ignored by git,
which means they won't be committed anyway.
"""

from pathlib import Path
from typing import List, Set
import fnmatch


class GitignoreParser:
    """Parse and match against .gitignore patterns."""
    
    def __init__(self, gitignore_path: Path = None, repo_path: Path = None):
        """
        Initialize with path to .gitignore file.
        
        Args:
            gitignore_path: Path to .gitignore file
            repo_path: Root of git repo (look for .gitignore here)
        """
        self.patterns = []
        self.negated_patterns = []
        
        if gitignore_path:
            self._load_from_file(gitignore_path)
        elif repo_path:
            gitignore_path = repo_path / ".gitignore"
            if gitignore_path.exists():
                self._load_from_file(gitignore_path)
    
    def _load_from_file(self, gitignore_path: Path):
        """Load patterns from .gitignore file."""
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle negation patterns (!)
                if line.startswith('!'):
                    pattern = line[1:].strip()
                    self.negated_patterns.append(pattern)
                else:
                    self.patterns.append(line)
        
        except Exception:
            pass
    
    def should_ignore(self, file_path: Path) -> bool:
        """
        Check if file should be ignored based on .gitignore rules.
        
        Args:
            file_path: Path to check (relative to repo root)
            
        Returns:
            True if file matches ignore pattern, False otherwise
        """
        # Convert to string for matching (normalize path separators)
        path_str = str(file_path).replace("\\", "/")
        
        # Check if negated (explicitly included)
        for pattern in self.negated_patterns:
            if self._matches_pattern(path_str, pattern):
                return False
        
        # Check if ignored
        for pattern in self.patterns:
            if self._matches_pattern(path_str, pattern):
                return True
        
        return False
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Match a path against a gitignore pattern."""
        # Normalize path separators
        path = path.replace("\\", "/")
        pattern = pattern.replace("\\", "/")
        
        # Handle directory patterns
        if pattern.endswith('/'):
            pattern = pattern.rstrip('/')
            return path.startswith(pattern) or f"/{path.strip('/')}".startswith(f"/{pattern}/")
        
        # Simple wildcard matching
        if fnmatch.fnmatch(path, pattern):
            return True
        if fnmatch.fnmatch(path, f"*/{pattern}"):
            return True
        
        return False


def get_gitignore_parser(repo_path: Path = None) -> GitignoreParser:
    """
    Get a GitignoreParser for the current/given repo.
    
    Args:
        repo_path: Path to git repo root
        
    Returns:
        GitignoreParser instance
    """
    if repo_path is None:
        repo_path = Path.cwd()
    
    return GitignoreParser(repo_path=repo_path)


# Default patterns to ignore (security-related, auto-excluded)
DEFAULT_IGNORE_PATTERNS = [
    "node_modules",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "__pycache__",
    ".git",
    "venv",
    ".venv",
    "dist",
    "build",
    ".egg-info",
    ".pytest_cache",
    ".coverage",
]


def should_ignore_by_default(file_path: Path) -> bool:
    """Check against hardcoded list of always-ignore patterns."""
    # Convert to string and normalize path separators
    path_str = str(file_path).replace("\\", "/").lower()
    
    for pattern in DEFAULT_IGNORE_PATTERNS:
        # Try exact match
        if fnmatch.fnmatch(path_str, pattern):
            return True
        # Try wildcard match with /
        if fnmatch.fnmatch(path_str, f"*/{pattern}"):
            return True
        # Try partial match for directories
        if f"/{pattern}/" in f"/{path_str}/":
            return True
        # Check if pattern is in the path
        if f"/{pattern}" in f"/{path_str}":
            return True
    
    return False