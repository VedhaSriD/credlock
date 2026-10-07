"""
Configuration management.
"""

import json
from pathlib import Path
from typing import Dict, Any


CONFIG_FILE = Path.home() / ".credlock" / "config.json"


DEFAULT_CONFIG = {
    "storage_dir": str(Path.home() / ".credlock"),
    "custom_patterns": {},
    "ignored_files": [],
}


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    """Save configuration to file."""
    try:
        CONFIG_FILE.parent.mkdir(exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def get_config_value(key: str, default: Any = None) -> Any:
    """Get a config value."""
    config = load_config()
    return config.get(key, default)