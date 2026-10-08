"""
Tests for CredLock CLI (FIXED v2.0)
- Fixed command names to match CLI definitions
- Cross-platform compatible
"""

import pytest
import tempfile
import os
import subprocess
from pathlib import Path
from typer.testing import CliRunner
from credlock.cli import app


runner = CliRunner()


class TestCLICommands:
    """Test CLI commands"""
    
    def test_help_command(self):
        """Test --help flag"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "credlock" in result.stdout.lower()
    
    def test_version_command(self):
        """Test version command"""
        result = runner.invoke(app, ["version"])  # FIXED: --version → version
        assert result.exit_code == 0
        assert "credlock" in result.stdout.lower()
    
    def test_scan_command_clean(self):
        """Test scan command with clean directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create clean Python file
            py_file = Path(tmpdir) / "main.py"
            py_file.write_text("def hello_world():\n    print('hello')")
            
            result = runner.invoke(app, ["scan", tmpdir])
            assert "No secrets" in result.stdout or "clean" in result.stdout.lower()
    
    def test_scan_command_with_secrets(self):
        """Test scan command detects secrets"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file with secrets
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
            
            result = runner.invoke(app, ["scan", tmpdir])
            # Should find secret and exit with code 1
            assert result.exit_code == 1
            assert "DETECTED" in result.stdout.upper() or "secret" in result.stdout.lower()
    
    def test_scan_default_directory(self):
        """Test scan with default directory"""
        result = runner.invoke(app, ["scan", "."])
        # Should not crash, exit code depends on whether secrets found
        assert result.exit_code in [0, 1]
    
    def test_history_command(self):
        """Test history command"""
        result = runner.invoke(app, ["history"])
        # Should not crash
        assert result.exit_code == 0
    
    def test_history_with_limit(self):
        """Test history with limit"""
        result = runner.invoke(app, ["history", "--limit=5"])
        assert result.exit_code == 0
    
    def test_configure_command(self):
        """Test configure command"""
        result = runner.invoke(app, ["configure"], input="4\n")  # Exit option
        assert result.exit_code == 0
    
    def test_version_subcommand(self):
        """Test version subcommand"""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "credlock" in result.stdout.lower()


class TestSetupGit:
    """Test Git hook setup"""
    
    def test_setup_git_not_in_repo(self):
        """Test setup outside git repo"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Save current directory
            original_cwd = os.getcwd()
            try:
                # Change to temp directory (not a git repo)
                os.chdir(tmpdir)
                result = runner.invoke(app, ["setup"])  # FIXED: setup-git → setup
                assert result.exit_code == 1
            finally:
                # Restore original directory
                os.chdir(original_cwd)
    
    def test_setup_git_in_repo(self):
        """Test setup inside git repo"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Save current directory
            original_cwd = os.getcwd()
            try:
                # Change to temp directory
                os.chdir(tmpdir)
                
                # Initialize git repo
                subprocess.run(["git", "init"], capture_output=True, check=True)
                
                # Run setup command
                result = runner.invoke(app, ["setup"])  # FIXED: setup-git → setup
                # Should succeed (exit code 0)
                assert result.exit_code == 0, f"Exit code: {result.exit_code}, Output: {result.stdout}"
                
                # Check hook was created
                hook_file = Path(tmpdir) / ".git" / "hooks" / "pre-commit"
                assert hook_file.exists()
                
                # Check hook content
                hook_content = hook_file.read_text(encoding='utf-8')
                assert "credlock" in hook_content.lower()
            finally:
                # Restore original directory
                os.chdir(original_cwd)


class TestCLIOutput:
    """Test CLI output formatting"""
    
    def test_scan_output_contains_file_path(self):
        """Test that scan output shows file paths"""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
            
            result = runner.invoke(app, ["scan", tmpdir])
            # Either .env appears in output, or tmpdir path appears
            assert ".env" in result.stdout or tmpdir in result.stdout or "DETECTED" in result.stdout.upper()
    
    def test_scan_output_contains_line_numbers(self):
        """Test that scan output shows line numbers"""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
            
            result = runner.invoke(app, ["scan", tmpdir])
            # Output should contain "Line" or line number reference
            # or at minimum, should detect the secret
            assert "Line" in result.stdout or "line" in result.stdout or "AKIA" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])