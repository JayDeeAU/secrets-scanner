"""
Enhanced Python Secrets Scanner

A powerful and maintainable tool for detecting hardcoded credentials, exposed sensitive data,
and other security issues in source code.
"""

__version__ = "1.0.0"

# Export main classes for easy importing
from .scanner import SecretsScanner, Finding
from .config_manager import ConfigManager, Severity, RiskType
from .pattern_manager import PatternManager
from .git_utils import GitUtils
from .allowlist_manager import AllowlistManager

__all__ = [
    'SecretsScanner', 
    'Finding', 
    'ConfigManager', 
    'PatternManager', 
    'GitUtils', 
    'AllowlistManager',
    'Severity',
    'RiskType'
]
