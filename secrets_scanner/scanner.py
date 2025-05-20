#!/usr/bin/env python3
"""
Main scanner module for the enhanced Python secrets scanner.
"""

import os
import sys
import re
from typing import List, Dict, Tuple, Optional, Set, Any, Union
from pathlib import Path

from .config_manager import ConfigManager, Severity, RiskType
from .pattern_manager import PatternManager
from .git_utils import GitUtils
from .allowlist_manager import AllowlistManager
from .finding import Finding


class GitHistoryScanner:
    """
    Scanner for Git history to find sensitive data in previously committed files.
    
    This class handles scanning files that appear in Git history but may now be
    gitignored, to identify potentially leaked secrets.
    """
    
    def __init__(self, scanner, repo_path="."):
        """
        Initialize the GitHistoryScanner.
        
        Args:
            scanner: The main SecretsScanner instance
            repo_path: Path to the Git repository
        """
        self.scanner = scanner
        self.repo_path = repo_path
        self.is_git_repo = self._check_is_git_repo()
    
    def _check_is_git_repo(self) -> bool:
        """
        Check if the directory is a Git repository.
        
        Returns:
            True if the directory is a Git repository, False otherwise
        """
        return GitUtils.is_git_repository(self.repo_path)
    
    def scan_historical_files(self, deep_scan: bool = False) -> List[Finding]:
        """
        Scan files from Git history for secrets.
        
        Args:
            deep_scan: If True, perform a more thorough scan of Git history
            
        Returns:
            List of findings in historical files
        """
        if not self.is_git_repo:
            print("⚠️ Not a Git repository. Skipping Git history scan.")
            return []
        
        findings = []
        
        # Get files from Git history that are now gitignored
        historical_files = GitUtils.get_historical_files(self.repo_path)
        
        if historical_files:
            print(f"🔍 Found {len(historical_files)} historical files to scan")
            
            # Group files by tracking status
            tracked_files = [(path, True) for path, tracked in historical_files if tracked]
            untracked_files = [(path, False) for path, tracked in historical_files if not tracked]
            
            if tracked_files:
                print(f"⚠️ {len(tracked_files)} files are gitignored but still tracked (high risk)")
            
            if untracked_files:
                print(f"ℹ️ {len(untracked_files)} files are gitignored and not tracked")
            
            # Scan all historical files
            for file_path, is_tracked in historical_files:
                # Check if file should be scanned based on patterns
                if not self.scanner.pattern_manager.should_scan_file(file_path):
                    continue
                
                print(f"  Scanning historical file: {file_path}" +
                      (" (still tracked)" if is_tracked else ""))
                
                # Scan the file for secrets
                file_findings = self.scanner.scan_file(file_path)
                
                # Tag findings appropriately
                for finding in file_findings:
                    finding.is_gitignored = True
                    finding.in_git_history = True
                    finding.is_still_tracked = is_tracked
                    
                    # Increase severity for tracked historical files
                    if is_tracked and finding.severity != Severity.HIGH:
                        finding.severity = Severity.HIGH
                        finding.description += " (Gitignored but still tracked in Git)"
                
                findings.extend(file_findings)
        
        # Optionally perform a deeper scan of Git objects
        if deep_scan:
            print("🔍 Performing deep scan of Git history...")
            blob_findings = self._scan_git_objects()
            findings.extend(blob_findings)
        
        return findings
    
    def _scan_git_objects(self) -> List[Finding]:
        """
        Scan Git objects (blobs) for secrets.
        
        This performs a more thorough scan by examining Git objects directly,
        rather than just current files.
        
        Returns:
            List of findings in Git objects
        """
        if not self.is_git_repo:
            return []
        
        findings = []
        
        try:
            # Get all blob objects from Git (limit to reasonable sample size)
            result = subprocess.run(
                ["git", "rev-list", "--objects", "--all", "--max-count=1000"],
                cwd=self.repo_path, stdout=subprocess.PIPE, text=True, check=True
            )
            
            # Process each line to extract blob and path
            blob_paths = {}
            for line in result.stdout.strip().split('\n'):
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    blob_hash, path = parts
                    # Only keep files we'd normally scan
                    if self.scanner.pattern_manager.should_scan_file(path):
                        blob_paths[blob_hash] = path
            
            if blob_paths:
                print(f"🔍 Deep scanning {len(blob_paths)} Git objects...")
                
                # Sample a reasonable number of blobs to scan
                import random
                sample_size = min(100, len(blob_paths))
                samples = random.sample(list(blob_paths.items()), sample_size) if sample_size > 0 else []
                
                for blob_hash, path in samples:
                    # Get blob content
                    cat_file = subprocess.run(
                        ["git", "cat-file", "-p", blob_hash],
                        cwd=self.repo_path, stdout=subprocess.PIPE, text=True, check=True
                    )
                    content = cat_file.stdout
                    
                    # Scan the content with the same pattern logic
                    for i, line in enumerate(content.split('\n'), 1):
                        # Skip if line should be excluded
                        if self.scanner.pattern_manager.should_exclude_line(line):
                            continue
                        
                        # Check for matches using the pattern manager
                        matches = self.scanner.pattern_manager.match_line(line)
                        
                        for pattern_def, pattern_str in matches:
                            # All Git history findings are HIGH severity
                            severity = Severity.HIGH
                            risk_type = self.scanner.pattern_manager.get_risk_type_for_pattern(pattern_def)
                            description = f"Found in Git history blob: {self.scanner.pattern_manager.get_description_for_pattern(pattern_def)}"
                            
                            finding = Finding(
                                file_path=f"[Git blob] {path}",
                                line_number=i,
                                line_content=line.strip(),
                                pattern=pattern_str,
                                severity=severity,
                                risk_type=risk_type,
                                description=description,
                                is_gitignored=False,
                                in_git_history=True
                            )
                            
                            # Skip if allowlisted
                            if self.scanner.allowlist_manager.is_allowlisted(finding):
                                continue
                            
                            findings.append(finding)
            
            return findings
            
        except Exception as e:
            print(f"⚠️ Error scanning Git objects: {e}")
            return []


class SecretsScanner:
    """
    Main secrets scanner class.
    
    This class orchestrates the entire scanning process, including pattern matching,
    Git history analysis, and integration with detect-secrets.
    """
    
    def __init__(self, mode: str = "comprehensive", verbose: bool = False, 
                high_only: bool = False, allowlist_file: str = ".secrets-allowlist.yaml",
                directory: str = ".", scan_gitignored: bool = False,
                check_git_history: bool = False, deep_scan: bool = False,
                use_detect_secrets: bool = True, config_file: Optional[str] = None):
        """
        Initialize the SecretsScanner with the given settings.
        
        Args:
            mode: Scanning mode, either "basic" or "comprehensive"
            verbose: Whether to show verbose output
            high_only: Whether to only report high severity findings
            allowlist_file: Path to the allowlist file
            directory: Directory to scan
            scan_gitignored: Whether to scan gitignored files
            check_git_history: Whether to check Git history
            deep_scan: Whether to perform a deep scan of Git history
            use_detect_secrets: Whether to use the detect-secrets library
            config_file: Path to a configuration file
        """
        self.mode = mode
        self.verbose = verbose
        self.high_only = high_only
        self.allowlist_file = allowlist_file
        self.directory = directory
        self.scan_gitignored = scan_gitignored
        self.check_git_history = check_git_history
        self.deep_scan = deep_scan
        self.use_detect_secrets = use_detect_secrets
        self.findings = []
        
        # Initialize config manager
        self.config_manager = ConfigManager(config_file=config_file, verbose=verbose)
        
        # Initialize pattern manager
        self.pattern_manager = PatternManager(self.config_manager, mode)
        
        # Initialize allowlist manager
        self.allowlist_manager = AllowlistManager(allowlist_file)
        
        # Check if detect-secrets is available
        if self.use_detect_secrets:
            self._check_detect_secrets()
        
        # Check if we're in a Git repository
        self.is_git_repo = GitUtils.is_git_repository(directory)
        if self.check_git_history and not self.is_git_repo:
            print("⚠️ Warning: --check-git-history specified but not in a Git repository. Feature will be disabled.")
            self.check_git_history = False
    
    def _check_detect_secrets(self) -> None:
        """
        Check if detect-secrets library is available and configured.
        
        This method attempts to import the detect-secrets library and sets
        the use_detect_secrets flag accordingly.
        """
        try:
            import detect_secrets
            print("✓ detect-secrets library found and will be used for additional scanning")
        except ImportError as e:
            print(f"⚠️ Warning: detect-secrets library not found: {e}")
            print("   Install with: pip install detect-secrets")
            self.use_detect_secrets = False
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of findings in the file
        """
        findings = []
        
        # Skip if file doesn't match our criteria
        if not self.pattern_manager.should_scan_file(file_path):
            return findings
        
        # Determine if this is a config file
        is_config_file = self.pattern_manager.is_config_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    # Skip if line should be excluded
                    if self.pattern_manager.should_exclude_line(line):
                        continue
                    
                    # Check line against patterns
                    matches = self.pattern_manager.match_line(line)
                    
                    for pattern_def, pattern_str in matches:
                        # Get severity and risk type from pattern definition
                        severity = self.pattern_manager.get_severity_for_pattern(pattern_def)
                        risk_type = self.pattern_manager.get_risk_type_for_pattern(pattern_def)
                        description = self.pattern_manager.get_description_for_pattern(pattern_def)
                        
                        # If it's a config file, consider increasing severity
                        if is_config_file and severity != Severity.HIGH:
                            # Higher severity for sensitive items in config files
                            if "token" in line.lower() or "password" in line.lower() or "secret" in line.lower():
                                severity = Severity.HIGH
                                description += " (in config file)"
                        
                        # Create finding
                        finding = Finding(
                            file_path=file_path,
                            line_number=i,
                            line_content=line.strip(),
                            pattern=pattern_str,
                            severity=severity,
                            risk_type=risk_type,
                            description=description
                        )
                        
                        # Skip if allowlisted
                        if self.allowlist_manager.is_allowlisted(finding):
                            if self.verbose:
                                print(f"  → Allowlisted finding: {finding.file_path}:{finding.line_number}")
                            continue
                        
                        # Skip if high-only mode and not high severity
                        if self.high_only and finding.severity != Severity.HIGH:
                            continue
                        
                        findings.append(finding)
            
            return findings
        except Exception as e:
            print(f"⚠️ Warning: Could not scan file {file_path}: {e}")
            return []
    
    def _get_line_content(self, file_path: str, line_number: int) -> str:
        """
        Get the content of a specific line in a file.
        
        Args:
            file_path: Path to the file
            line_number: Line number to get
            
        Returns:
            The content of the line
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if i == line_number:
                        return line.strip()
            return ""
        except Exception:
            return "<could not read line>"
    
    def _get_context_lines(self, file_path: str, line_number: int, context: int = 2) -> List[str]:
        """
        Get context lines around a line in a file.
        
        Args:
            file_path: Path to the file
            line_number: Line number to get context around
            context: Number of context lines to get
            
        Returns:
            List of context lines
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            start = max(0, line_number - context - 1)
            end = min(len(lines), line_number + context)
            
            return lines[start:end]
        except Exception as e:
            return [f"[Could not read file: {e}]"]
    
    def _collect_files_to_scan(self) -> List[str]:
        """
        Collect all files that should be scanned.
        
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        gitignored_files = []
        
        # Walk the directory and collect files
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file should be scanned based on patterns
                if not self.pattern_manager.should_scan_file(file_path):
                    continue
                
                # Check if file is gitignored
                is_gitignored = False
                if self.is_git_repo:
                    is_gitignored = GitUtils.is_file_gitignored(file_path, self.directory)
                
                # Skip gitignored files if not scanning them
                if is_gitignored:
                    if self.scan_gitignored:
                        gitignored_files.append(file_path)
                    else:
                        continue
                else:
                    files_to_scan.append(file_path)
        
        # Add gitignored files to scan list if requested
        if self.scan_gitignored and gitignored_files:
            files_to_scan.extend(gitignored_files)
            print(f"🔎 Will scan {len(files_to_scan)} files ({len(gitignored_files)} gitignored)")
        else:
            print(f"🔎 Will scan {len(files_to_scan)} files")
        
        return files_to_scan
    
    def _run_detect_secrets_scan(self, files_to_scan: List[str]) -> List[Finding]:
        """
        Run a scan using detect-secrets library for additional pattern coverage.
        
        Args:
            files_to_scan: List of file paths to scan
            
        Returns:
            List of findings from detect-secrets
        """
        if not self.use_detect_secrets:
            return []
        
        try:
            # Import required detect-secrets components
            from detect_secrets import SecretsCollection
            from detect_secrets.settings import transient_settings
            
            print("🔍 Running detect-secrets scanner for additional coverage")
            
            # Configure the plugins with proper settings
            plugins_config = [
                # Structured secrets detectors
                {'name': 'AWSKeyDetector'},
                {'name': 'AzureStorageKeyDetector'},
                {'name': 'BasicAuthDetector'},
                {'name': 'CloudantDetector'},
                {'name': 'DiscordBotTokenDetector'},
                {'name': 'GitHubTokenDetector'},
                {'name': 'GitLabTokenDetector'},
                {'name': 'JwtTokenDetector'},
                {'name': 'MailchimpDetector'},
                {'name': 'NpmDetector'},
                {'name': 'OpenAIDetector'},
                {'name': 'PrivateKeyDetector'},
                {'name': 'PypiTokenDetector'},
                {'name': 'SendGridDetector'},
                {'name': 'SlackDetector'},
                {'name': 'SoftlayerDetector'},
                {'name': 'SquareOAuthDetector'},
                {'name': 'StripeDetector'},
                {'name': 'TelegramBotTokenDetector'},
                {'name': 'TwilioKeyDetector'},
                
                # Entropy-based detectors with configured limits
                {'name': 'Base64HighEntropyString', 'limit': 4.5},
                {'name': 'HexHighEntropyString', 'limit': 3.0},
                
                # Keyword-based detector
                {'name': 'KeywordDetector'}
            ]
            
            # Create the configuration dictionary
            config = {
                'plugins_used': plugins_config
            }
            
            findings = []
            
            # Use transient_settings to configure the plugins
            with transient_settings(config):
                # Create a SecretsCollection to store detected secrets
                secrets = SecretsCollection()
                
                # Scan each file
                for file_idx, file_path in enumerate(files_to_scan):
                    if self.verbose and file_idx % 50 == 0:
                        print(f"  [{file_idx+1}/{len(files_to_scan)}] detect-secrets scanning: {file_path}")
                    
                    try:
                        # Scan the file
                        secrets.scan_file(file_path)
                    except Exception as e:
                        if self.verbose:
                            print(f"  ⚠️ detect-secrets error scanning {file_path}: {e}")
                
                # Process results
                try:
                    for filename in secrets.files:
                        # Process each secret in the file
                        for secret in secrets[filename]:
                            try:
                                # Get line content
                                line_number = secret.line_number  # Adjust for 0-based index
                                line_content = self._get_line_content(filename, line_number)
                                
                                # Get the secret type
                                secret_type = getattr(secret, 'type', 'Unknown')
                                
                                # Determine severity (most detect-secrets findings are HIGH)
                                severity = Severity.HIGH
                                
                                # Check for lower severity based on context
                                if any(term in line_content.lower() for term in ["test", "example", "sample", "mock"]):
                                    severity = Severity.MEDIUM
                                
                                # Determine if file is gitignored
                                is_gitignored = False
                                if self.is_git_repo:
                                    is_gitignored = GitUtils.is_file_gitignored(filename, self.directory)
                                
                                # Determine risk type based on secret type
                                risk_type = RiskType.HARDCODED_SECRET
                                
                                # Create a finding
                                finding = Finding(
                                    file_path=filename,
                                    line_number=line_number,
                                    line_content=line_content,
                                    pattern=f"detect-secrets:{secret_type}",
                                    severity=severity,
                                    risk_type=risk_type,
                                    description=f"Secret detected by detect-secrets: {secret_type}",
                                    is_gitignored=is_gitignored
                                )
                                
                                # Skip if allowlisted
                                if self.allowlist_manager.is_allowlisted(finding):
                                    if self.verbose:
                                        print(f"  → Allowlisted finding: {finding.file_path}:{finding.line_number}")
                                    continue
                                
                                # Skip if high-only mode and not high severity
                                if self.high_only and severity != Severity.HIGH:
                                    if self.verbose:
                                        print(f"  → Skipping non-high severity finding: {finding.file_path}:{finding.line_number}")
                                    continue
                                
                                findings.append(finding)
                            except Exception as e:
                                if self.verbose:
                                    print(f"  ⚠️ Error processing detect-secrets finding: {e}")
                except Exception as e:
                    print(f"⚠️ Error accessing files property: {e}")
                    print("Skipping detect-secrets results processing")
            
            print(f"  ✓ detect-secrets found {len(findings)} potential secrets")
            return findings
            
        except ImportError as e:
            print(f"⚠️ Warning: detect-secrets library not available: {e}")
            print("   Install with: pip install detect-secrets")
            return []
        except Exception as e:
            print(f"⚠️ Error using detect-secrets: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return []
    
    def scan(self) -> List[Finding]:
        """
        Main scanning method that coordinates the entire scanning process.
        
        This method collects files to scan, runs the different scanning methods,
        and combines the results.
        
        Returns:
            List of all findings
        """
        print(f"🔍 Starting secret scan in: {os.path.abspath(self.directory)}")
        print(f"   Mode: {self.mode}")
        
        # Step 1: Collect files to scan
        files_to_scan = self._collect_files_to_scan()
        if not files_to_scan:
            print("No files to scan!")
            return []
        
        # Step 2: Scan files with custom patterns
        pattern_findings = []
        for file_idx, file_path in enumerate(files_to_scan):
            if self.verbose or file_idx % 100 == 0:
                print(f"  [{file_idx+1}/{len(files_to_scan)}] Scanning: {file_path}")
            
            file_findings = self.scan_file(file_path)
            pattern_findings.extend(file_findings)
        
        print(f"  ✓ Pattern scanner found {len(pattern_findings)} potential secrets")
        
        # Step 3: Run detect-secrets scanner if enabled
        detect_secrets_findings = []
        if self.use_detect_secrets:
            detect_secrets_findings = self._run_detect_secrets_scan(files_to_scan)
        
        # Step 4: Handle Git history if requested
        git_findings = []
        if self.check_git_history:
            git_scanner = GitHistoryScanner(self, self.directory)
            git_findings = git_scanner.scan_historical_files(self.deep_scan)
            
            if git_findings:
                print(f"  ✓ Git history scan found {len(git_findings)} potential secrets")
        
        # Step 5: Combine all findings and remove duplicates
        all_findings = pattern_findings + detect_secrets_findings + git_findings
        
        # Remove duplicates based on fingerprint
        unique_findings = {}
        for finding in all_findings:
            if finding.fingerprint not in unique_findings:
                unique_findings[finding.fingerprint] = finding
            else:
                # If duplicate, keep the higher severity one
                existing = unique_findings[finding.fingerprint]
                if (finding.severity == Severity.HIGH and existing.severity != Severity.HIGH) or \
                   (finding.severity == Severity.MEDIUM and existing.severity == Severity.LOW):
                    unique_findings[finding.fingerprint] = finding
        
        self.findings = list(unique_findings.values())
        print(f"✓ Scan complete: Found {len(self.findings)} unique findings")
        
        return self.findings
    
    def print_report(self) -> bool:
        """
        Print a comprehensive report of all findings.
        
        This method groups findings by severity and risk type, and provides detailed
        information about each finding, including remediation guidance.
        
        Returns:
            True if any high severity findings were found, False otherwise
        """
        if not self.findings:
            print("\n✅ No secrets detected in the scanned files.")
            return False
        
        # Group findings by severity
        high_findings = [f for f in self.findings if f.severity == Severity.HIGH]
        medium_findings = [f for f in self.findings if f.severity == Severity.MEDIUM]
        low_findings = [f for f in self.findings if f.severity == Severity.LOW]
        
        # Group findings by risk type
        hardcoded_findings = [f for f in self.findings if f.risk_type == RiskType.HARDCODED_SECRET]
        log_exposure_findings = [f for f in self.findings if f.risk_type == RiskType.DATA_EXPOSURE_LOGS]
        response_exposure_findings = [f for f in self.findings if f.risk_type == RiskType.DATA_EXPOSURE_RESPONSE]
        config_findings = [f for f in self.findings if f.risk_type == RiskType.SENSITIVE_CONFIG]
        
        # Group findings by git status
        gitignored_findings = [f for f in self.findings if getattr(f, 'is_gitignored', False)]
        historical_findings = [f for f in self.findings if getattr(f, 'in_git_history', False)]
        
        # Get unique files with findings
        unique_files = set(f.file_path for f in self.findings)
        
        print("\n=== SCAN SUMMARY ===\n")
        print(f"🚨 Found {len(self.findings)} potential secrets in {len(unique_files)} files.")
        print(f"  🔴 HIGH SEVERITY: {len(high_findings)} findings")
        print(f"  🟠 MEDIUM SEVERITY: {len(medium_findings)} findings")
        print(f"  🟡 LOW SEVERITY: {len(low_findings)} findings")
        
        if gitignored_findings:
            print(f"\n  🔍 GITIGNORED FILES: {len(gitignored_findings)} findings in gitignored files")
        
        if historical_findings:
            print(f"\n  🔍 HISTORICAL FINDINGS: {len(historical_findings)} findings in files from Git history")
            tracked_historical = [f for f in historical_findings if getattr(f, 'is_still_tracked', False)]
            if tracked_historical:
                print(f"    ⚠️ CRITICAL: {len(tracked_historical)} findings in files that are STILL TRACKED (needs immediate attention)")
        
        print("\n=== FINDINGS BY RISK TYPE ===\n")
        print("  📊 FINDINGS BY RISK TYPE:")
        print(f"     - {len(hardcoded_findings)} hardcoded secrets")
        print(f"     - {len(log_exposure_findings)} data exposures in logs")
        print(f"     - {len(response_exposure_findings)} data exposures in responses")
        print(f"     - {len(config_findings)} sensitive configuration items")
        print()
        
        # First highlight critical files
        critical_files = {}
        for finding in self.findings:
            if finding.severity == Severity.HIGH:
                if finding.file_path not in critical_files:
                    critical_files[finding.file_path] = []
                critical_files[finding.file_path].append(finding)
        
        if critical_files:
            print("=== CRITICAL FILES ===\n")
            print("The following files have HIGH severity findings that need immediate attention:")
            for file_path, findings in critical_files.items():
                print(f"\n⚠️  {file_path}: {len(findings)} HIGH severity findings")
        
        # Historical files still tracked (highest risk)
        tracked_historical_files = {}
        for finding in historical_findings:
            if getattr(finding, 'is_still_tracked', False):
                if finding.file_path not in tracked_historical_files:
                    tracked_historical_files[finding.file_path] = []
                tracked_historical_files[finding.file_path].append(finding)
        
        if tracked_historical_files:
            print("\n=== CRITICAL: HISTORICAL FILES STILL TRACKED ===\n")
            print("The following files contain sensitive information, are in .gitignore,")
            print("but are STILL TRACKED by Git. These need immediate attention!")
            
            for file_path, findings in tracked_historical_files.items():
                high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
                
                print(f"\n⚠️  CRITICAL: {file_path}")
                print(f"   {len(findings)} findings ({high_count} HIGH severity)")
                print("   This file needs to be removed from Git tracking!")
                
                # Show a sample finding
                if findings:
                    print("\n   Sample finding:")
                    finding = findings[0]
                    print(f"   Line {finding.line_number}: {finding.line_content}")
            
            print("\n   To remove these files from Git tracking (but keep them locally):")
            for file_path in tracked_historical_files:
                rel_path = os.path.relpath(file_path, self.directory)
                print(f"   git rm --cached \"{rel_path}\"")
            print("   git commit -m \"Remove sensitive files that should be gitignored\"")
            print("   git push")
            print()
        
        # Now show details for all findings
        print("=== DETAILED MATCHES ===\n")
        
        # Display detailed matches
        for finding in self.findings:
            # Prepare status indicators
            status_indicators = []
            if getattr(finding, 'is_gitignored', False):
                status_indicators.append("🔍 GITIGNORED")
            if getattr(finding, 'in_git_history', False):
                status_indicators.append("⚠️ IN GIT HISTORY")
            if getattr(finding, 'is_still_tracked', False):
                status_indicators.append("⚠️ STILL TRACKED")
            
            status_str = f" [{' - '.join(status_indicators)}]" if status_indicators else ""
            
            print(f"⚠️  {finding.severity.value} - {finding.risk_type.value} - MATCH FOUND in {finding.file_path} line {finding.line_number}{status_str}:")
            print(f"   FINGERPRINT: {finding.fingerprint}")
            print(f"   PATTERN: {finding.pattern}")
            
            if finding.description:
                print(f"   DESCRIPTION: {finding.description}")
            
            print("   CODE CONTEXT:")
            print("   " + "-" * 50)
            
            context_lines = self._get_context_lines(finding.file_path, finding.line_number)
            start_line = max(1, finding.line_number - 2)
            
            for i, line in enumerate(context_lines):
                line_num = start_line + i
                if line_num == finding.line_number:
                    print(f"   {line_num:3d} | {line.rstrip()}  <-- ⚠️ FINDING HERE")
                else:
                    print(f"   {line_num:3d} | {line.rstrip()}")
            
            print("   " + "-" * 50)
            print()
        
        # Generate allowlist file
        allowlist_file = "secrets_findings.yaml"
        self.allowlist_manager.generate_allowlist_from_findings(self.findings, allowlist_file)
        
        # Provide remediation guidance
        print("\n=== REMEDIATION GUIDANCE ===\n")
        print("🛠️  Next steps by risk type:")
        
        if historical_findings:
            print("\n=== HISTORICAL FILE CLEANUP GUIDANCE ===\n")
            print("Some sensitive files have been detected in Git history. To properly clean them:")
            
            print("\n1. For files still tracked by Git, first remove them from tracking:")
            if tracked_historical_files:
                for file_path in tracked_historical_files:
                    rel_path = os.path.relpath(file_path, self.directory)
                    print(f"   git rm --cached \"{rel_path}\"")
                print("   git commit -m \"Remove sensitive files that should be gitignored\"")
                print("   git push")
        
                print("\n2. To completely remove these files from Git history, use BFG Repo-Cleaner:")
                print("   a. Download BFG from: https://rtyley.github.io/bfg-repo-cleaner/")
                
                # Create file listing all historical files with findings
                history_files = set(f.file_path for f in historical_findings)
                with open("sensitive-git-history-files.txt", "w") as f:
                    for file_path in history_files:
                        rel_path = os.path.relpath(file_path, self.directory)
                        f.write(f"{rel_path}\n")
                
                print("   b. We've created a file with all sensitive files: sensitive-git-history-files.txt")
                print("   c. Follow these steps to clean the history:")
                print("      git clone --mirror git://your-repo.git repo.git")
                print("      java -jar bfg.jar --delete-files sensitive-git-history-files.txt repo.git")
                print("      cd repo.git")
                print("      git reflog expire --expire=now --all")
                print("      git gc --prune=now --aggressive")
                print("      git push")
                
                print("\n⚠️ WARNING: This will rewrite Git history. Coordinate with your team before proceeding.")
   
        if hardcoded_findings:
            print()
            print(f"   🔑 HARDCODED SECRETS ({len(hardcoded_findings)} findings):")
            print("     - Remove hardcoded secrets from code and use environment variables instead")
            print("     - Store secrets in a secure vault like AWS Secrets Manager, HashiCorp Vault, etc.")
            print("     - Use a .env file (not committed to version control) for local development")
            print("     - Consider any already-committed secrets compromised and rotate them immediately")
        
        if log_exposure_findings:
            print()
            print(f"   📝 DATA EXPOSURE IN LOGS ({len(log_exposure_findings)} findings):")
            print("     - Never log sensitive values like passwords, tokens, or keys")
            print("     - Use redaction patterns like console.log('token:', '***REDACTED***')")
            print("     - Create helper functions that automatically redact sensitive fields")
            print("     - Implement proper debug levels to control what gets logged")
        
        if response_exposure_findings:
            print()
            print(f"   🌐 DATA EXPOSURE IN RESPONSES ({len(response_exposure_findings)} findings):")
            print("     - Never return sensitive values in API responses")
            print("     - Create data sanitization functions that strip sensitive fields before sending")
            print("     - Use response schemas or serializers that explicitly define what gets returned")
            print("     - Add unit tests to verify sensitive data isn't leaked in responses")
        
        if config_findings:
            print()
            print(f"   ⚙️ SENSITIVE CONFIGURATION ({len(config_findings)} findings):")
            print("     - Move sensitive values from configuration files to environment variables")
            print("     - Use .env.example files with placeholder values as templates")
            print("     - In CI/CD environments, use secure environment variable storage")
            print("     - For infrastructure-as-code, use secure variable handling mechanisms")
        
        print()
        print("🔁 CI/CD Integration:")
        print(f"   A file '{allowlist_file}' has been created with all findings.")
        print("   To suppress known/acceptable findings:")
        print(f"   1. Review the findings and update {self.allowlist_file} with acceptable ones")
        print("   2. Run with --high-only flag to only fail on high severity findings")
        print("   Example: secrets-scanner --high-only")
        
        print()
        print("🔄 Next Steps:")
        print("   1. Review all HIGH and MEDIUM severity findings immediately")
        print("   2. For each finding, follow the remediation guidance to fix the issue")
        print("   3. If a finding is a false positive, add it to the allowlist file")
        print("   4. For gitignored files with secrets that were previously committed, rotate those secrets")
        print("   5. Consider implementing pre-commit hooks to prevent new secrets from being committed")
        print("   6. Run the scanner regularly as part of your CI/CD pipeline using the --high-only flag")
        print()
        
        if high_findings:
            print("⚠️ HIGH SEVERITY FINDINGS REQUIRE IMMEDIATE ATTENTION")
            print("   Secrets exposed in your codebase pose a significant security risk and should be")
            print("   addressed as soon as possible. Consider rotating any exposed credentials.")
       
        # Return True if there are any high severity findings
        return len(high_findings) > 0
