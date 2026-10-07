# tests/test_gitignore.py
"""Test .gitignore parsing."""

import pytest
from pathlib import Path
from credlock.gitignore_parser import GitignoreParser, should_ignore_by_default


class TestGitignore:
    """Test .gitignore parsing and matching."""
    
    def test_default_ignore_patterns(self):
        """Test default patterns are ignored."""
        assert should_ignore_by_default(Path("node_modules/package.json"))
        assert should_ignore_by_default(Path("package-lock.json"))
        assert should_ignore_by_default(Path("__pycache__/module.pyc"))
        assert should_ignore_by_default(Path("venv/lib/python.so"))
    
    def test_default_not_ignore(self):
        """Test that regular files are not ignored by default."""
        assert not should_ignore_by_default(Path("src/main.py"))
        assert not should_ignore_by_default(Path(".env"))  # .env is NOT auto-ignored
        assert not should_ignore_by_default(Path("README.md"))
    
    def test_gitignore_parser(self, tmp_path):
        """Test parsing .gitignore file."""
        # Create .gitignore
        gitignore_path = tmp_path / ".gitignore"
        gitignore_path.write_text("""
.env
node_modules/
*.log
        """)
        
        # Create parser
        parser = GitignoreParser(gitignore_path=gitignore_path)
        
        # Test matching
        assert parser.should_ignore(Path(".env"))
        assert parser.should_ignore(Path("node_modules/pkg"))
        assert parser.should_ignore(Path("debug.log"))
        assert not parser.should_ignore(Path("src/main.py"))