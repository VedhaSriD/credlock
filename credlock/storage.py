"""
Store and retrieve scan history.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict


class ScanStorage:
    """Store scan results to disk."""
    
    def __init__(self, storage_dir: Path = None):
        """Initialize storage directory."""
        if storage_dir is None:
            storage_dir = Path.home() / ".credlock"
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.history_file = self.storage_dir / "history.json"
    
    def save_scan(self, findings: List[Dict]):
        """
        Save a scan result.
        
        Args:
            findings: List of finding dictionaries
        """
        try:
            # Load existing history
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            else:
                history = []
            
            # Add new scan
            scan_record = {
                "timestamp": datetime.now().isoformat(),
                "findings_count": len(findings),
                "findings": findings
            }
            
            history.append(scan_record)
            
            # Save updated history (keep last 100 scans)
            history = history[-100:]
            
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
        
        except Exception as e:
            print(f"Warning: Could not save scan history: {e}")
    
    def get_history(self, limit: int = 10) -> List[Dict]:
        """Get recent scan history."""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
            
            return history[-limit:]
        except Exception:
            return []
    
    def clear_history(self):
        """Clear scan history."""
        if self.history_file.exists():
            self.history_file.unlink()


# Global storage instance
_storage = ScanStorage()


def save_scan(findings: List[Dict]):
    """Save scan results."""
    _storage.save_scan(findings)


def get_history(limit: int = 10) -> List[Dict]:
    """Get scan history."""
    return _storage.get_history(limit)


def clear_history():
    """Clear history."""
    _storage.clear_history()


def get_storage_path() -> Path:
    """Get the storage directory path."""
    return _storage.storage_dir