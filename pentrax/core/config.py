#!/usr/bin/env python3
"""
PENTRA-X Configuration Management
Load and manage configuration from YAML file.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

from .colors import Colors


# Default configuration
DEFAULT_CONFIG = {
    'version': '2.0.0',
    'general': {
        'verbose': False,
        'log_level': 'INFO',
        'results_dir': '~/.pentrax/results',
        'logs_dir': '~/.pentrax/logs',
    },
    'network': {
        'timeout': 10,
        'max_threads': 50,
        'default_ports': '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080',
    },
    'web': {
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'timeout': 30,
        'follow_redirects': True,
        'max_redirects': 5,
    },
    'wireless': {
        'default_interface': 'wlan0',
        'monitor_interface': 'wlan0mon',
        'handshake_dir': '~/.pentrax/handshakes',
    },
    'wordlists': {
        'directory': '/usr/share/wordlists',
        'passwords': '/usr/share/wordlists/rockyou.txt',
        'directories': '/usr/share/wordlists/dirb/common.txt',
        'subdomains': '/usr/share/wordlists/subdomains.txt',
    },
    'tools': {
        'nmap_path': 'nmap',
        'hydra_path': 'hydra',
        'sqlmap_path': 'sqlmap',
        'gobuster_path': 'gobuster',
        'aircrack_path': 'aircrack-ng',
        'bettercap_path': 'bettercap',
    },
    'display': {
        'clear_screen': True,
        'show_banner': True,
        'color_output': True,
        'animation_speed': 0.03,
    },
}


class Config:
    """Configuration manager for PENTRA-X."""
    
    CONFIG_PATHS = [
        Path.cwd() / 'config.yaml',
        Path.cwd() / 'config.yml',
        Path.home() / '.pentrax' / 'config.yaml',
        Path('/etc/pentrax/config.yaml'),
    ]
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration.
        
        Args:
            config_path: Optional explicit path to config file
        """
        self._config: Dict[str, Any] = DEFAULT_CONFIG.copy()
        self._config_path: Optional[Path] = None
        
        # Find and load config file
        if config_path:
            self._load_config(config_path)
        else:
            for path in self.CONFIG_PATHS:
                if path.exists():
                    self._load_config(path)
                    break
    
    def _load_config(self, path: Path) -> None:
        """Load configuration from YAML file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
            
            # Deep merge with defaults
            self._deep_merge(self._config, user_config)
            self._config_path = path
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Failed to load config from {path}: {e}{Colors.ENDC}")
    
    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key using dot notation (e.g., 'network.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        # Expand ~ in paths
        if isinstance(value, str) and value.startswith('~'):
            value = os.path.expanduser(value)
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key using dot notation
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, path: Optional[Path] = None) -> bool:
        """
        Save configuration to YAML file.
        
        Args:
            path: Path to save to (uses loaded path if not specified)
            
        Returns:
            True if saved successfully
        """
        save_path = path or self._config_path
        if not save_path:
            save_path = Path.home() / '.pentrax' / 'config.yaml'
        
        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save config: {e}{Colors.ENDC}")
            return False
    
    @property
    def config_path(self) -> Optional[Path]:
        """Get the loaded config file path."""
        return self._config_path
    
    def __repr__(self) -> str:
        return f"Config(path={self._config_path})"


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create the global config instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def reload_config(path: Optional[Path] = None) -> Config:
    """Reload configuration from file."""
    global _config
    _config = Config(path)
    return _config
