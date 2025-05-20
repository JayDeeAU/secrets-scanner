#!/usr/bin/env python3
"""
Command-line interface for the enhanced Python secrets scanner.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from .scanner import SecretsScanner


def get_version() -> str:
    """Get the version of the secrets scanner package."""
    from . import __version__
    return __version__


def main() -> int:
    """
    Main entry point for the secrets scanner CLI.
    
    Returns:
        Exit code (0 for success, 1 for findings, 2 for errors)
    """
    parser = argparse.ArgumentParser(
        description="Enhanced Python Secrets Scanner - Detects hardcoded credentials and sensitive data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrets-scanner                                # Run in comprehensive mode
  secrets-scanner --mode basic                   # Run in basic mode (fewer false positives)
  secrets-scanner --verbose                      # Run with verbose output
  secrets-scanner --high-only                    # Only report high severity findings
  secrets-scanner --config-file my_config.yaml   # Use custom configuration file
  secrets-scanner --allowlist-file custom.yaml   # Use custom allowlist file
  secrets-scanner --check-git-history            # Check Git history
  secrets-scanner --deep-scan                    # Perform deep scan
        """
    )
    parser.add_argument("--mode", choices=["basic", "comprehensive", "strict", "loose"], default="comprehensive",
                        help="Scanning mode: 'basic' (fewer false positives) or 'comprehensive' (more thorough)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show more detailed output")
    parser.add_argument("--high-only", action="store_true",
                        help="Only report HIGH severity findings (good for CI/CD)")
    parser.add_argument("--allowlist-file", default=".secrets-allowlist.yaml",
                        help="Path to allowlist file")
    parser.add_argument("--directory", default=".",
                        help="Directory to scan")
    parser.add_argument("--scan-gitignored", action="store_true",
                        help="Also scan files excluded by .gitignore")
    parser.add_argument("--check-git-history", action="store_true",
                        help="Check for secrets in gitignored files that were previously committed")
    parser.add_argument("--deep-scan", action="store_true",
                        help="Perform a deep scan (slower but more thorough)")
    parser.add_argument("--skip-detect-secrets", action="store_true",
                        help="Skip using detect-secrets library")
    parser.add_argument("--config-file", default=None,
                        help="Path to configuration file")
    parser.add_argument("--generate-allowlist", action="store_true",
                        help="Generate an allowlist file from findings")
    parser.add_argument("--version", action="store_true",
                        help="Show version information and exit")
    
    args = parser.parse_args()
    
    # Show version if requested
    if args.version:
        print(f"Enhanced Python Secrets Scanner v{get_version()}")
        return 0
    
    # Print header
    print("=" * 60)
    print(f"📦 Enhanced Python Secrets Scanner v{get_version()}")
    print("=" * 60)
    
    # Support legacy mode names
    if args.mode == "strict":
        print("⚠️ 'strict' mode has been renamed to 'basic'")
        args.mode = "basic"
    elif args.mode == "loose":
        print("⚠️ 'loose' mode has been renamed to 'comprehensive'")
        args.mode = "comprehensive"
    
    try:
        scanner = SecretsScanner(
            mode=args.mode,
            verbose=args.verbose,
            high_only=args.high_only,
            allowlist_file=args.allowlist_file,
            directory=args.directory,
            scan_gitignored=args.scan_gitignored,
            check_git_history=args.check_git_history,
            deep_scan=args.deep_scan,
            use_detect_secrets=not args.skip_detect_secrets,
            config_file=args.config_file
        )
        
        # Run the scan
        findings = scanner.scan()
        
        # Print report
        high_findings_exist = scanner.print_report()
        
        # Generate allowlist if requested
        if args.generate_allowlist and findings:
            allowlist_file = "generated_allowlist.yaml"
            scanner.allowlist_manager.generate_allowlist_from_findings(findings, allowlist_file)
            print(f"\n✓ Generated allowlist file: {allowlist_file}")
            print("  Review and move approved items to your main allowlist file")
        
        # Exit with the appropriate status code
        if args.high_only:
            if high_findings_exist:
                print("❌ CI/CD Check Failed: High severity findings detected")
                return 1
            else:
                print("✅ CI/CD Check Passed: No high severity findings detected")
                return 0
        elif findings:
            return 1
        else:
            return 0
            
    except Exception as e:
        print(f"❌ Error running secrets scanner: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
