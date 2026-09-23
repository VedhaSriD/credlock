"""
CredLock Git Hook (FIXED)
Manage Git pre-commit hooks - removed emoji for Windows compatibility
"""

import os
from pathlib import Path


class GitHookManager:
    """Manage Git pre-commit hooks"""
    
    @staticmethod
    def install_hook(repo_path: str = ".") -> bool:
        """
        Install pre-commit hook
        
        Args:
            repo_path: Path to git repository
            
        Returns:
            True if successful
        """
        git_dir = Path(repo_path) / ".git"
        if not git_dir.exists():
            return False
        
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        
        hook_file = hooks_dir / "pre-commit"
        
        # FIXED: Removed emoji characters that break Windows CP1252 encoding
        hook_content = """#!/bin/bash
# CredLock - Automatic Secret Detection
# Prevents accidental secret commits

credlock scan

if [ $? -ne 0 ]; then
    echo ""
    echo "[CredLock] Secrets detected. Commit blocked."
    echo "Fix the issues above before trying again."
    exit 1
fi

exit 0
"""
        
        try:
            # FIXED: Explicitly use UTF-8 encoding for Windows compatibility
            with open(hook_file, 'w', encoding='utf-8') as f:
                f.write(hook_content)
            
            os.chmod(hook_file, 0o755)
            return True
        except Exception as e:
            print(f"Error installing hook: {e}")
            return False
    
    @staticmethod
    def uninstall_hook(repo_path: str = ".") -> bool:
        """
        Remove pre-commit hook
        
        Args:
            repo_path: Path to git repository
            
        Returns:
            True if successful
        """
        hook_file = Path(repo_path) / ".git" / "hooks" / "pre-commit"
        
        try:
            if hook_file.exists():
                hook_file.unlink()
            return True
        except:
            return False
    
    @staticmethod
    def hook_exists(repo_path: str = ".") -> bool:
        """Check if pre-commit hook exists"""
        hook_file = Path(repo_path) / ".git" / "hooks" / "pre-commit"
        return hook_file.exists()