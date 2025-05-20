#!/usr/bin/env python3
"""
Allowlist manager for the enhanced Python secrets scanner.
"""

import os
import re
import yaml
import json
from datetime import datetime
from typing import Dict, List, Any, Optional


class AllowlistManager:
    """
    Manages the allowlist of acceptable findings.
    
    This class handles loading, checking, and updating the allowlist of
    findings that should be ignored during scanning.
    """
    
    def __init__(self, allowlist_file: str = ".secrets-allowlist.yaml"):
        """
        Initialize the AllowlistManager with the given allowlist file.
        
        Args:
            allowlist_file: Path to the allowlist file
        """
        self.allowlist_file = allowlist_file
        self.allowlist = self._load_allowlist()
    
    def _load_allowlist(self) -> Dict[str, Dict[str, str]]:
        """
        Load the allowlist from the allowlist file.
        
        Returns:
            Dictionary mapping fingerprints to information about the allowlisted finding
        """
        if not os.path.exists(self.allowlist_file):
            print(f"ℹ️ No allowlist file found at {self.allowlist_file}")
            return {}
        
        try:
            with open(self.allowlist_file, 'r') as f:
                if self.allowlist_file.endswith('.yaml') or self.allowlist_file.endswith('.yml'):
                    allowlist = yaml.safe_load(f) or {}
                elif self.allowlist_file.endswith('.json'):
                    allowlist = json.load(f)
                else:
                    # Simple text file format
                    allowlist = {}
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        allowlist[line] = {"reason": "Preapproved"}
            
            print(f"✓ Loaded {len(allowlist)} allowlisted findings")
            return allowlist
        except Exception as e:
            print(f"⚠️ Warning: Could not read allowlist file: {e}")
            return {}
    
    def is_allowlisted(self, finding: Any) -> bool:
        """
        Check if a finding is in the allowlist.
        
        Args:
            finding: The finding to check
            
        Returns:
            True if the finding is allowlisted, False otherwise
        """
        # Check exact fingerprint
        if finding.fingerprint in self.allowlist:
            return True
        
        # Check full fingerprint
        if finding.full_fingerprint in self.allowlist:
            return True
        
        # Check pattern-based fingerprints
        for pattern, info in self.allowlist.items():
            if '*' in pattern:
                # Convert glob pattern to regex
                regex_pattern = pattern.replace('*', '.*')
                if re.match(regex_pattern, finding.fingerprint) or re.match(regex_pattern, finding.full_fingerprint):
                    return True
        
        return False
    
    def add_finding_to_allowlist(self, finding: Any, reason: str = "", added_by: str = "") -> bool:
        """
        Add a finding to the allowlist.
        
        Args:
            finding: The finding to add
            reason: Reason for allowlisting
            added_by: User who added the finding
            
        Returns:
            True if the finding was added, False otherwise
        """
        if not reason:
            reason = "Manually allowlisted"
        
        if not added_by:
            added_by = os.getenv("USER", "unknown")
        
        # Add to allowlist
        self.allowlist[finding.full_fingerprint] = {
            "reason": reason,
            "added_by": added_by,
            "date_added": datetime.now().isoformat()
        }
        
        # Save allowlist
        try:
            with open(self.allowlist_file, 'w') as f:
                if self.allowlist_file.endswith('.yaml') or self.allowlist_file.endswith('.yml'):
                    yaml.dump(self.allowlist, f, default_flow_style=False)
                elif self.allowlist_file.endswith('.json'):
                    json.dump(self.allowlist, f, indent=2)
                else:
                    # Simple text file format
                    for fingerprint, info in self.allowlist.items():
                        reason_str = f" # {info.get('reason')}" if 'reason' in info else ""
                        f.write(f"{fingerprint}{reason_str}\n")
            
            print(f"✓ Added finding to allowlist: {finding.full_fingerprint}")
            return True
        except Exception as e:
            print(f"⚠️ Error saving allowlist: {e}")
            return False
    
    def generate_allowlist_from_findings(self, findings: List[Any], output_file: str) -> bool:
        """
        Generate an allowlist file from a list of findings.
        
        Args:
            findings: List of findings to add to the allowlist
            output_file: Path to the output file
            
        Returns:
            True if the allowlist was generated, False otherwise
        """
        try:
            allowlist = {}
            for finding in findings:
                allowlist[finding.full_fingerprint] = {
                    "reason": "TO REVIEW",
                    "added_by": os.getenv("USER", "unknown"),
                    "date_added": datetime.now().isoformat()
                }
            
            with open(output_file, 'w') as f:
                if output_file.endswith('.yaml') or output_file.endswith('.yml'):
                    yaml.dump(allowlist, f, default_flow_style=False)
                elif output_file.endswith('.json'):
                    json.dump(allowlist, f, indent=2)
                else:
                    # Simple text file format
                    for fingerprint in allowlist:
                        f.write(f"{fingerprint}\n")
            
            print(f"✓ Generated allowlist file: {output_file}")
            return True
        except Exception as e:
            print(f"⚠️ Error generating allowlist: {e}")
            return False
