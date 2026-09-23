"""
CredLock Config
Configuration management
"""

import yaml
from pathlib import Path
from typing import Dict


class Config:
    """Manage CredLock configuration"""
    
    def __init__(self):
        """Initialize configuration"""
        self.config_dir = Path.home() / ".credlock"
        self.config_file = self.config_dir / "config.yaml"
        self.config_dir.mkdir(exist_ok=True)
    
    def load(self) -> Dict:
        """Load configuration from file"""
        if not self.config_file.exists():
            return self.get_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                return config if config else self.get_default_config()
        except:
            return self.get_default_config()
    
    def save(self, config: Dict):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "patterns_enabled": 50,
            "custom_patterns": {},
            "ignored_files": [
                ".git/*",
                "node_modules/*",
                "__pycache__/*",
                "venv/*",
                "env/*",
                "*.pyc",
            ],
            "auto_scan": True,
            "scan_depth": "recursive",
            "report_format": "terminal",
        }
    
    def add_custom_pattern(self, name: str, regex: str):
        """Add custom pattern"""
        config = self.load()
        config["custom_patterns"][name] = regex
        self.save(config)
    
    def remove_custom_pattern(self, name: str):
        """Remove custom pattern"""
        config = self.load()
        if name in config["custom_patterns"]:
            del config["custom_patterns"][name]
        self.save(config)
    
    def get_custom_patterns(self) -> Dict:
        """Get custom patterns"""
        config = self.load()
        return config.get("custom_patterns", {})


# Global config instance
_config = Config()


def load_config() -> Dict:
    """Load configuration"""
    return _config.load()


def save_config(config: Dict):
    """Save configuration"""
    return _config.save(config)


def get_default_config() -> Dict:
    """Get default configuration"""
    return _config.get_default_config()


def add_custom_pattern(name: str, regex: str):
    """Add custom pattern"""
    return _config.add_custom_pattern(name, regex)