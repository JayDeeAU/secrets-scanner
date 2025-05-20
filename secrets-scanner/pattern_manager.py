#!/usr/bin/env python3
"""
PatternManager for Enhanced Python Secrets Scanner.

This module handles pattern matching and management using the new configuration system.
"""

import os
import re
import fnmatch
from typing import List, Dict, Tuple, Optional, Pattern, Any, Union

from .config_manager import ConfigManager, Severity, RiskType


class PatternManager:
    """
    Manages patterns for secret scanning using the new configuration system.
    
    This class handles loading, compiling, and managing patterns for detecting
    secrets in various types of files. It uses the ConfigManager to access
    patterns defined in the configuration file.
    """
    
    def __init__(self, config_manager: ConfigManager, mode: str = "comprehensive"):
        """
        Initialize the PatternManager with the given ConfigManager and mode.
        
        Args:
            config_manager: The ConfigManager instance
            mode: Scanning mode, either "basic" or "comprehensive"
        """
        self.config_manager = config_manager
        self.mode = mode
        
        # Validate mode
        if mode not in ["basic", "comprehensive"]:
            print(f"⚠️ Warning: Unknown mode '{mode}'. Using 'comprehensive' mode.")
            self.mode = "comprehensive"
        
        # For backward compatibility
        if mode == "strict":
            print("ℹ️ 'strict' mode has been renamed to 'basic'")
            self.mode = "basic"
        elif mode == "loose":
            print("ℹ️ 'loose' mode has been renamed to 'comprehensive'")
            self.mode = "comprehensive"
        
        # Get patterns for the current mode
        self.patterns = self.config_manager.get_compiled_patterns_for_mode(self.mode)
        
    def should_scan_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned based on extensions and exclusions.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        return self.config_manager.should_scan_file(file_path)
    
    def is_config_file(self, file_path: str) -> bool:
        """
        Check if a file is a configuration file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file is a configuration file, False otherwise
        """
        return self.config_manager.is_config_file(file_path)
    
    def should_exclude_line(self, line: str) -> bool:
        """
        Check if a line should be excluded from scanning.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line should be excluded, False otherwise
        """
        return self.config_manager.should_exclude_line(line)
    
    def should_allowlist_line(self, line: str) -> bool:
        """
        Check if a line should be automatically allowlisted.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line should be allowlisted, False otherwise
        """
        return self.config_manager.should_allowlist_line(line)
    
    def get_patterns(self) -> List[Tuple[Pattern, Dict[str, Any]]]:
        """
        Get all compiled patterns for the current mode.
        
        Returns:
            List of tuples containing (compiled_pattern, pattern_metadata)
        """
        return self.patterns
    
    def get_severity_for_pattern(self, pattern_def: Dict[str, Any]) -> Severity:
        """
        Get the severity for a pattern definition.
        
        Args:
            pattern_def: Pattern definition dictionary
            
        Returns:
            Severity enum value
        """
        return self.config_manager.pattern_to_severity(pattern_def)
    
    def get_risk_type_for_pattern(self, pattern_def: Dict[str, Any]) -> RiskType:
        """
        Get the risk type for a pattern definition.
        
        Args:
            pattern_def: Pattern definition dictionary
            
        Returns:
            RiskType enum value
        """
        return self.config_manager.pattern_to_risk_type(pattern_def)
    
    def get_description_for_pattern(self, pattern_def: Dict[str, Any]) -> str:
        """
        Get the description for a pattern definition.
        
        Args:
            pattern_def: Pattern definition dictionary
            
        Returns:
            Description string
        """
        return pattern_def.get('description', '')
    
    def match_line(self, line: str) -> List[Tuple[Dict[str, Any], str]]:
        """
        Check if a line matches any pattern.
        
        Args:
            line: The line to check
            
        Returns:
            List of tuples containing (pattern_def, matching_pattern_str)
        """
        # Skip if line should be excluded
        if self.should_exclude_line(line):
            return []
        
        # Skip if line should be allowlisted
        if self.should_allowlist_line(line):
            return []
        
        matches = []
        
        # Check each pattern
        for compiled_pattern, pattern_def in self.patterns:
            match = compiled_pattern.search(line)
            if match:
                pattern_str = pattern_def.get('pattern', '')
                matches.append((pattern_def, pattern_str))
        
        return matches
