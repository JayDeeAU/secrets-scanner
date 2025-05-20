# Enhanced Python Secrets Scanner

A powerful and maintainable tool for detecting hardcoded credentials, exposed sensitive data, and other security issues in source code.

## Features

- Configuration-based pattern management
- Detects hardcoded secrets and credentials
- Finds instances where sensitive data might be exposed through logs or responses
- Manages acceptable findings via an allowlist file
- Provides clear, actionable output sorted by severity
- Supports both basic and comprehensive scanning modes
- Integrates with CI/CD pipelines
- Integrates with detect-secrets library for additional scanning coverage
- Provides Git history analysis to find sensitive data in previously committed files

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secrets-scanner.git
cd secrets-scanner

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

- PyYAML
- detect-secrets (optional, but recommended for additional coverage)

## Usage

```bash
# Basic usage
python secrets_scanner.py

# Scan with basic mode (fewer false positives)
python secrets_scanner.py --mode basic

# Only report high severity findings (good for CI/CD)
python secrets_scanner.py --high-only

# Check Git history for secrets
python secrets_scanner.py --check-git-history

# Use a custom configuration file
python secrets_scanner.py --config-file my_config.yaml

# Use a custom allowlist file
python secrets_scanner.py --allowlist-file my_allowlist.yaml
```

## Scanning Modes

- **Basic Mode** (formerly "strict"): Uses patterns with higher confidence and fewer false positives. Good for CI/CD pipelines where you want to minimize noise.
- **Comprehensive Mode** (formerly "loose"): Uses all patterns for maximum coverage. Good for thorough security audits.

## Configuration

The scanner now uses a YAML configuration file to define patterns and scanning behavior. This makes it much easier to maintain and extend.

Default configuration is embedded, but you can provide your own with `--config-file`.

### Configuration Structure

```yaml
# High-level structure
metadata:
  version: "1.0.0"
  description: "Configuration for enhanced Python secrets scanner"

file_selection:
  file_patterns: [...]     # Files to include in scanning
  config_file_patterns: [...]  # Configuration files that need special handling
  excluded_paths: [...]    # Paths to exclude from scanning

secret_patterns:
  api_credentials: [...]   # API keys, tokens, client secrets
  password_credentials: [...] # Password patterns
  database_credentials: [...] # Database connection strings
  service_specific_credentials: [...] # Service-specific patterns
  private_keys: [...]      # Private keys and certificates

exposure_patterns:
  logging_exposure: [...]  # Logging exposure patterns
  response_exposure: [...] # Response exposure patterns
  config_sections: [...]   # Config section patterns

filter_patterns:
  exclusions: [...]        # Patterns to exclude from matching
  allowlist_patterns: [...] # Patterns that are automatically allowlisted

scan_modes:
  basic: { ... }           # Basic scan mode configuration
  comprehensive: { ... }   # Comprehensive scan mode configuration
```

### Pattern Definition

Each pattern is defined with metadata:

```yaml
- pattern: "password[\"\\\'=:\\s]+(?!password|test)[A-Za-z0-9_.-]{8,}"
  severity: "HIGH"
  description: "Password with 8+ characters"
  risk_type: "HARDCODED_SECRET"
  example: "password=\"mypassword123\""
  modes: ["basic", "comprehensive"]
```

## Allowlisting

You can create an allowlist file to suppress known/acceptable findings:

```yaml
# .secrets-allowlist.yaml
"src/config.py:42:password[\"\\'=:\\s]+[A-Za-z0-9_.-]{8,}":
  reason: "Test environment password"
  added_by: "security-team"
  date_added: "2025-05-21T14:30:00"
```

## Git History Scanning

The scanner can detect secrets in files that were previously committed to Git but are now gitignored:

```bash
python secrets_scanner.py --check-git-history
```

For more thorough scanning across all Git versions:

```bash
python secrets_scanner.py --check-git-history --deep-scan
```

## CI/CD Integration

```yaml
# Example GitHub Action
name: Secrets Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
    - name: Scan for secrets
      run: |
        python secrets_scanner.py --high-only
```

## Migration from Previous Version

If you're migrating from the previous version:

1. Rename your scan mode from "strict" to "basic" or "loose" to "comprehensive"
2. Consider creating a custom configuration file for more control
3. Your existing allowlist files will continue to work

The scanner will automatically handle the mode name mapping for backward compatibility.
