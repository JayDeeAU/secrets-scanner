#!/usr/bin/env python3
"""
ConfigManager for Enhanced Python Secrets Scanner.

This module handles loading, parsing, and managing configuration for the secrets scanner,
including pattern definitions, file selection criteria, and scan modes.
"""

import os
import sys
import yaml
import json
import re
import importlib.resources
from enum import Enum
from typing import List, Dict, Set, Tuple, Optional, Pattern, Any, Union
from pathlib import Path


class Severity(Enum):
    """Enumeration for different severity levels of findings."""
    HIGH = "🔴 HIGH SEVERITY"
    MEDIUM = "🟠 MEDIUM SEVERITY"
    LOW = "🟡 LOW SEVERITY"


class RiskType(Enum):
    """Enumeration for different risk types."""
    HARDCODED_SECRET = "HARDCODED SECRET"
    DATA_EXPOSURE_LOGS = "DATA EXPOSURE IN LOGS"
    DATA_EXPOSURE_RESPONSE = "DATA EXPOSURE IN RESPONSE"
    SENSITIVE_CONFIG = "SENSITIVE CONFIG SECTION"


class ConfigManager:
    """
    Manages loading and accessing pattern configurations for the secrets scanner.
    
    This class is responsible for loading pattern definitions from a configuration file,
    compiling regex patterns, and providing access to specific pattern groups based
    on scan mode and other criteria.
    """
    
    def __init__(self, config_file: Optional[str] = None, verbose: bool = False):
        """
        Initialize the ConfigManager with the specified configuration file.
        
        Args:
            config_file: Path to the configuration file (YAML or JSON)
            verbose: Whether to show verbose output
        """
        self.config_file = config_file
        self.verbose = verbose
        self.config = {}
        
        # Compiled patterns cache
        self.compiled_patterns = {}
        
        # Load configuration
        self.config = self._load_config(config_file)
        
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults.
        
        Args:
            config_file: Path to the configuration file
            
        Returns:
            Dictionary containing the loaded configuration
        """
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                        config = yaml.safe_load(f)
                    elif config_file.endswith('.json'):
                        config = json.load(f)
                    else:
                        print(f"⚠️ Unsupported config file format: {config_file}")
                        print("Falling back to default embedded configuration")
                        return self._get_default_config()
                
                if not config:
                    print(f"⚠️ Empty configuration file: {config_file}")
                    print("Falling back to default embedded configuration")
                    return self._get_default_config()
                
                if self.verbose:
                    print(f"✓ Loaded configuration from {config_file}")
                
                return config
            except Exception as e:
                print(f"⚠️ Error loading configuration from {config_file}: {e}")
                print("Falling back to default embedded configuration")
                return self._get_default_config()
        else:
            if config_file:
                print(f"⚠️ Configuration file not found: {config_file}")
                print("Using default embedded configuration")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get the default embedded configuration.
        
        Returns:
            Dictionary containing the default configuration
        """
        # Try to locate the default configuration within the package
        try:
            # First try using importlib.resources (Python 3.7+)
            try:
                from importlib import resources
                # Try to read from the package
                if resources.is_resource("secrets_scanner", "default_config.yaml"):
                    with resources.open_text("secrets_scanner", "default_config.yaml") as f:
                        return yaml.safe_load(f)
            except (ImportError, FileNotFoundError):
                # Fall back to looking in the module directory
                module_dir = os.path.dirname(os.path.abspath(__file__))
                default_config_path = os.path.join(module_dir, "default_config.yaml")
                
                if os.path.exists(default_config_path):
                    with open(default_config_path, 'r', encoding='utf-8') as f:
                        return yaml.safe_load(f)
        except Exception as e:
            print(f"⚠️ Error loading default configuration: {e}")
        
        # If all else fails, return a minimal embedded configuration
        print("Using minimal embedded configuration")
        return {
            "metadata": {
                "version": "1.0.0",
                "description": "Default embedded configuration for secrets scanner"
            },
            "file_selection": {
                "file_patterns": [
                    "*.env", ".env", "*.py", "*.json", "*.yaml", "*.yml", 
                    "*.js", "*.ts", "*.conf", "*.ini", "*.properties", "*.txt"
                ],
                "config_file_patterns": [
                    ".env", "*.env", "*.ini", "*.conf", "*.yaml", "*.yml", "config.*"
                ],
                "excluded_paths": [
                    "**/node_modules/**", "**/.git/**", "**/venv/**", "**/__pycache__/**"
                ]
            },
            "secret_patterns": {
                "api_credentials": [
                    {
                        "pattern": "api[_-]?key[\"\\\'=:\\s]+[A-Za-z0-9_.-]{10,}",
                        "severity": "HIGH",
                        "description": "API Key",
                        "risk_type": "HARDCODED_SECRET",
                        "modes": ["basic", "comprehensive"]
                    }
                ]
            },
            "filter_patterns": {
                "exclusions": [
                    {
                        "pattern": "example|sample|mock|dummy|test",
                        "description": "Test or example code"
                    }
                ]
            },
            "scan_modes": {
                "basic": {
                    "description": "Basic scan with higher confidence patterns",
                    "severity_filter": "HIGH",
                    "pattern_groups": ["api_credentials:basic"]
                },
                "comprehensive": {
                    "description": "Comprehensive scan with all patterns",
                    "severity_filter": "ALL",
                    "pattern_groups": ["api_credentials"]
                }
            }
        }
        
    def get_file_patterns(self) -> List[str]:
        """
        Get the list of file patterns to include in scanning.
        
        Returns:
            List of file patterns
        """
        return self.config.get('file_selection', {}).get('file_patterns', [])
    
    def get_config_file_patterns(self) -> List[str]:
        """
        Get the list of patterns that identify configuration files.
        
        Returns:
            List of configuration file patterns
        """
        return self.config.get('file_selection', {}).get('config_file_patterns', [])
    
    def get_excluded_paths(self) -> List[str]:
        """
        Get the list of paths to exclude from scanning.
        
        Returns:
            List of excluded path patterns
        """
        return self.config.get('file_selection', {}).get('excluded_paths', [])
    
    def get_exclusion_patterns(self) -> List[Dict[str, str]]:
        """
        Get the list of patterns to exclude from matching.
        
        Returns:
            List of exclusion patterns
        """
        return self.config.get('filter_patterns', {}).get('exclusions', [])
    
    def get_allowlist_patterns(self) -> List[Dict[str, str]]:
        """
        Get the list of patterns that are automatically allowlisted.
        
        Returns:
            List of allowlist patterns
        """
        return self.config.get('filter_patterns', {}).get('allowlist_patterns', [])
    
    def _compile_pattern(self, pattern_str: str) -> Pattern:
        """
        Compile a regex pattern.
        
        Args:
            pattern_str: The regex pattern string
            
        Returns:
            Compiled regex pattern
        """
        try:
            return re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            print(f"⚠️ Error compiling pattern '{pattern_str}': {e}")
            # Try a simplified version
            try:
                simplified = pattern_str.replace('\\s+', '\\s*').replace('{10,}', '{10,100}')
                compiled = re.compile(simplified, re.IGNORECASE)
                print(f"  ✓ Using simplified pattern instead: '{simplified}'")
                return compiled
            except re.error as e2:
                print(f"  ❌ Could not compile simplified pattern either: {e2}")
                # Return a pattern that won't match anything as a fallback
                return re.compile(r'^\b$')
    
    def _get_patterns_for_category(self, category: str, mode: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get patterns for a specific category and mode.
        
        Args:
            category: The pattern category to retrieve
            mode: Optional mode filter (e.g., 'basic', 'comprehensive')
            
        Returns:
            List of pattern definitions
        """
        patterns = []
        
        # Check in secret_patterns
        if 'secret_patterns' in self.config and category in self.config['secret_patterns']:
            for pattern_def in self.config['secret_patterns'][category]:
                if mode is None or 'modes' not in pattern_def or mode in pattern_def['modes']:
                    patterns.append(pattern_def)
        
        # Check in exposure_patterns
        if 'exposure_patterns' in self.config and category in self.config['exposure_patterns']:
            for pattern_def in self.config['exposure_patterns'][category]:
                if mode is None or 'modes' not in pattern_def or mode in pattern_def['modes']:
                    patterns.append(pattern_def)
        
        return patterns
    
    def get_compiled_patterns_for_mode(self, mode: str) -> List[Tuple[Pattern, Dict[str, Any]]]:
        """
        Get all compiled patterns for a specific scanning mode.
        
        Args:
            mode: The scanning mode ('basic' or 'comprehensive')
            
        Returns:
            List of tuples containing (compiled_pattern, pattern_metadata)
        """
        # Check if patterns are already compiled for this mode
        cache_key = f"mode_{mode}"
        if cache_key in self.compiled_patterns:
            return self.compiled_patterns[cache_key]
        
        patterns = []
        mode_config = self.config.get('scan_modes', {}).get(mode, {})
        
        # Get the pattern groups for this mode
        pattern_groups = mode_config.get('pattern_groups', [])
        
        # Collect patterns from each group
        for group_spec in pattern_groups:
            # Handle notation like "database_credentials:basic"
            if ':' in group_spec:
                group_name, group_mode = group_spec.split(':')
            else:
                group_name, group_mode = group_spec, mode
            
            # Get patterns for this group and mode
            group_patterns = self._get_patterns_for_category(group_name, group_mode)
            
            # Compile patterns
            for pattern_def in group_patterns:
                pattern_str = pattern_def.get('pattern', '')
                if pattern_str:
                    compiled_pattern = self._compile_pattern(pattern_str)
                    patterns.append((compiled_pattern, pattern_def))
        
        # Cache the compiled patterns
        self.compiled_patterns[cache_key] = patterns
        
        if self.verbose:
            print(f"✓ Compiled {len(patterns)} patterns for mode '{mode}'")
        
        return patterns
    
    def get_compiled_exclusion_patterns(self) -> List[Pattern]:
        """
        Get all compiled exclusion patterns.
        
        Returns:
            List of compiled exclusion patterns
        """
        # Check if patterns are already compiled
        cache_key = "exclusions"
        if cache_key in self.compiled_patterns:
            return self.compiled_patterns[cache_key]
        
        patterns = []
        for pattern_def in self.get_exclusion_patterns():
            pattern_str = pattern_def.get('pattern', '')
            if pattern_str:
                compiled_pattern = self._compile_pattern(pattern_str)
                patterns.append(compiled_pattern)
        
        # Cache the compiled patterns
        self.compiled_patterns[cache_key] = patterns
        
        return patterns
    
    def get_compiled_allowlist_patterns(self) -> List[Pattern]:
        """
        Get all compiled allowlist patterns.
        
        Returns:
            List of compiled allowlist patterns
        """
        # Check if patterns are already compiled
        cache_key = "allowlist"
        if cache_key in self.compiled_patterns:
            return self.compiled_patterns[cache_key]
        
        patterns = []
        for pattern_def in self.get_allowlist_patterns():
            pattern_str = pattern_def.get('pattern', '')
            if pattern_str:
                compiled_pattern = self._compile_pattern(pattern_str)
                patterns.append(compiled_pattern)
        
        # Cache the compiled patterns
        self.compiled_patterns[cache_key] = patterns
        
        return patterns
    
    def is_config_file(self, file_path: str) -> bool:
        """
        Check if a file is a configuration file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file is a configuration file, False otherwise
        """
        import fnmatch
        
        file_name = os.path.basename(file_path)
        
        for pattern in self.get_config_file_patterns():
            if fnmatch.fnmatch(file_name, pattern):
                return True
        
        return False
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned based on file patterns and exclusions.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        import fnmatch
        
        # Check excluded paths first
        for pattern in self.get_excluded_paths():
            if fnmatch.fnmatch(file_path, pattern):
                return False
        
        # Check if file matches any file patterns
        file_name = os.path.basename(file_path)
        for pattern in self.get_file_patterns():
            if fnmatch.fnmatch(file_name, pattern):
                return True
        
        return False
    
    def should_exclude_line(self, line: str) -> bool:
        """
        Check if a line should be excluded from scanning.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line should be excluded, False otherwise
        """
        for pattern in self.get_compiled_exclusion_patterns():
            if pattern.search(line):
                return True
        
        return False
    
    def should_allowlist_line(self, line: str) -> bool:
        """
        Check if a line should be automatically allowlisted.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line should be allowlisted, False otherwise
        """
        for pattern in self.get_compiled_allowlist_patterns():
            if pattern.search(line):
                return True
        
        return False
    
    def get_severity_filter(self, mode: str) -> Optional[str]:
        """
        Get the severity filter for a specific mode.
        
        Args:
            mode: The scanning mode
            
        Returns:
            Severity filter, or None if all severities should be included
        """
        mode_config = self.config.get('scan_modes', {}).get(mode, {})
        severity_filter = mode_config.get('severity_filter')
        
        # If 'ALL', return None to include all severities
        if severity_filter == 'ALL':
            return None
        
        return severity_filter
    
    def pattern_to_severity(self, pattern_def: Dict[str, Any]) -> Severity:
        """
        Get the severity for a pattern definition.
        
        Args:
            pattern_def: Pattern definition dictionary
            
        Returns:
            Severity enum value
        """
        severity_str = pattern_def.get('severity', 'LOW').upper()
        
        if severity_str == 'HIGH':
            return Severity.HIGH
        elif severity_str == 'MEDIUM':
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def pattern_to_risk_type(self, pattern_def: Dict[str, Any]) -> RiskType:
        """
        Get the risk type for a pattern definition.
        
        Args:
            pattern_def: Pattern definition dictionary
            
        Returns:
            RiskType enum value
        """
        risk_type_str = pattern_def.get('risk_type', 'HARDCODED_SECRET').upper()
        
        if risk_type_str == 'DATA_EXPOSURE_LOGS':
            return RiskType.DATA_EXPOSURE_LOGS
        elif risk_type_str == 'DATA_EXPOSURE_RESPONSE':
            return RiskType.DATA_EXPOSURE_RESPONSE
        elif risk_type_str == 'SENSITIVE_CONFIG':
            return RiskType.SENSITIVE_CONFIG
        else:
            return RiskType.HARDCODED_SECRET
