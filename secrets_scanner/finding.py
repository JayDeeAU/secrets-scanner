#!/usr/bin/env python3
"""
Finding class for the enhanced Python secrets scanner.
"""

from typing import Dict, Any
from .config_manager import Severity, RiskType


class Finding:
    """
    Class representing a secret finding.
    
    A Finding object contains all the information about a detected secret, including
    its location, content, pattern that matched it, severity, and risk type.
    """
    
    def __init__(self, file_path: str, line_number: int, 
                 line_content: str, pattern: str, 
                 severity: Severity = Severity.LOW, 
                 risk_type: RiskType = RiskType.HARDCODED_SECRET,
                 description: str = "",
                 is_gitignored: bool = False,
                 in_git_history: bool = False,
                 is_still_tracked: bool = False):
        """
        Initialize a Finding object with details about the detected secret.
        
        Args:
            file_path: Path to the file containing the secret
            line_number: Line number where the secret was found
            line_content: Content of the line containing the secret
            pattern: Pattern that matched to find this secret
            severity: Severity level of the finding
            risk_type: Type of risk this secret represents
            description: Optional description of the finding
            is_gitignored: Whether the file is gitignored
            in_git_history: Whether the file appears in Git history
            is_still_tracked: Whether the file is still tracked by Git
        """
        self.file_path = file_path
        self.line_number = line_number
        self.line_content = line_content
        self.pattern = pattern
        self.severity = severity
        self.risk_type = risk_type
        self.description = description
        self.is_gitignored = is_gitignored
        self.in_git_history = in_git_history
        self.is_still_tracked = is_still_tracked
        
        # Generate fingerprints for uniqueness and allowlisting
        self.fingerprint = f"{file_path}:{line_number}"
        self.full_fingerprint = f"{file_path}:{line_number}:{pattern}"
    
    def __str__(self) -> str:
        """Return a string representation of the finding."""
        return f"{self.severity.value} - {self.risk_type.value} in {self.file_path}:{self.line_number}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "pattern": self.pattern,
            "severity": self.severity.name,
            "risk_type": self.risk_type.name,
            "description": self.description,
            "is_gitignored": self.is_gitignored,
            "in_git_history": self.in_git_history,
            "is_still_tracked": self.is_still_tracked,
            "fingerprint": self.fingerprint,
            "full_fingerprint": self.full_fingerprint
        }
