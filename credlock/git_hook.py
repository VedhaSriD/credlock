"""
Git pre-commit hook integration.
"""

import os
from pathlib import Path
import subprocess


HOOK_SCRIPT = """#!/bin/sh
# CredLock pre-commit hook
# Prevents accidental credential commits

credlock scan --staged
"""


def setup_hook(force: bool = False) -> bool:
    """
    Install pre-commit hook in .git/hooks/
    
    Args:
        force: Overwrite existing hook
        
    Returns:
        True if successful
    """
    try:
        # Find .git directory
        git_dir = Path(".git")
        if not git_dir.exists():
            raise Exception("Not in a git repository")
        
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        
        hook_file = hooks_dir / "pre-commit"
        
        # Check if hook exists
        if hook_file.exists() and not force:
            raise Exception("Hook already exists. Use --force to overwrite")
        
        # Write hook
        hook_file.write_text(HOOK_SCRIPT)
        
        # Make executable on Unix
        os.chmod(hook_file, 0o755)
        
        return True
    
    except Exception as e:
        raise Exception(f"Failed to setup hook: {e}")


def remove_hook() -> bool:
    """Remove pre-commit hook."""
    try:
        hook_file = Path(".git/hooks/pre-commit")
        if hook_file.exists():
            hook_file.unlink()
        return True
    except Exception:
        return False


def is_in_git_repo() -> bool:
    """Check if we're in a git repository."""
    return Path(".git").exists()