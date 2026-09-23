"""
CredLock Storage
Local JSON-based storage for scan history
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict


class Storage:
    """Manage local storage of scan history"""
    
    def __init__(self):
        """Initialize storage"""
        self.storage_dir = Path.home() / ".credlock"
        self.history_file = self.storage_dir / "history.json"
        self.config_file = self.storage_dir / "config.yaml"
        
        # Create directory if doesn't exist
        self.storage_dir.mkdir(exist_ok=True)
    
    def save_scan(self, scan_data: Dict) -> str:
        """
        Save scan result to history
        
        Args:
            scan_data: Dictionary with scan information
            
        Returns:
            Scan ID
        """
        # Create scan ID based on timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = f"scan_{timestamp}_{len(self._load_all_scans())}"
        
        # Add metadata
        scan_data["scan_id"] = scan_id
        scan_data["timestamp"] = datetime.now().isoformat()
        
        # Load existing history
        history = self._load_all_scans()
        
        # Add new scan
        history.append(scan_data)
        
        # Keep only last 100 scans
        history = history[-100:]
        
        # Save to file
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
        
        return scan_id
    
    def _load_all_scans(self) -> List[Dict]:
        """Load all scans from history"""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except:
            return []
    
    def get_history(self, limit: int = 10) -> List[Dict]:
        """
        Get recent scan history
        
        Args:
            limit: Number of scans to return
            
        Returns:
            List of scan dictionaries
        """
        all_scans = self._load_all_scans()
        return all_scans[-limit:][::-1]  # Return reversed (newest first)
    
    def get_scan(self, scan_id: str) -> Dict:
        """Get specific scan by ID"""
        all_scans = self._load_all_scans()
        for scan in all_scans:
            if scan.get("scan_id") == scan_id:
                return scan
        return None
    
    def clear_history(self):
        """Clear all scan history"""
        self.history_file.write_text("[]")
    
    def get_storage_path(self) -> Path:
        """Get storage directory path"""
        return self.storage_dir
    
    def get_config_path(self) -> Path:
        """Get config file path"""
        return self.config_file


# Create global storage instance
_storage = Storage()


def save_scan(scan_data: Dict) -> str:
    """Save scan to storage"""
    return _storage.save_scan(scan_data)


def get_history(limit: int = 10) -> List[Dict]:
    """Get scan history"""
    return _storage.get_history(limit)


def get_scan(scan_id: str) -> Dict:
    """Get specific scan"""
    return _storage.get_scan(scan_id)


def clear_history():
    """Clear history"""
    return _storage.clear_history()


def get_storage_path() -> Path:
    """Get storage path"""
    return _storage.get_storage_path()


def get_config_path() -> Path:
    """Get config path"""
    return _storage.get_config_path()