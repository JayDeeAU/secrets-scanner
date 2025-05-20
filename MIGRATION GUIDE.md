# Migration Guide for Enhanced Secrets Scanner

This guide outlines the steps to migrate from the previous version of the secrets scanner to the new configuration-based version. The new version offers improved maintainability, better pattern organization, and reduced false positives.

## Key Changes

1. **Configuration-based pattern management**
   - Patterns are now defined in a YAML configuration file
   - Each pattern includes metadata like severity, description, and examples
   - Patterns are organized by purpose (API keys, passwords, etc.) rather than by severity

2. **Mode name changes**
   - "strict" mode → "basic" mode
   - "loose" mode → "comprehensive" mode
   - Old names are still supported for backward compatibility

3. **Reduced false positives**
   - Many broad patterns have been refined or removed
   - Added negative lookaheads to exclude common false positives
   - Patterns now exclude test/example code more effectively

4. **New features**
   - Automatic allowlisting of certain patterns
   - Better Git history scanning
   - Enhanced configuration for different scan modes

## Implementation Plan

### Phase 1: Install the New System

1. **Backup your existing scanner and configuration**
   ```bash
   cp secrets_scanner.py secrets_scanner.py.bak
   cp .secrets-allowlist.yaml .secrets-allowlist.yaml.bak
   ```

2. **Copy the new files into your project**
   - `secrets_scanner_refactored.py` → `secrets_scanner.py`
   - `config_manager.py`
   - `pattern_manager.py`
   - `secrets_scanner_config.yaml`

3. **Install required dependencies**
   ```bash
   pip install pyyaml
   ```

### Phase 2: Validate Existing Behavior

1. **Run scans with both versions on a sample repository**
   ```bash
   python secrets_scanner.py.bak --verbose > old_results.txt
   python secrets_scanner.py --verbose > new_results.txt
   ```

2. **Compare the results**
   - Check for any significant differences in findings
   - Verify that critical findings are still being detected
   - Note any false positives that are now correctly ignored

### Phase 3: Customize Configuration

1. **Review the default configuration file**
   - Open `secrets_scanner_config.yaml`
   - Understand the pattern organization and structure

2. **Add any custom patterns you had in the old version**
   - Find any custom patterns in your old scanner
   - Add them to the appropriate sections in the config file
   - Include metadata like severity, description, and examples

3. **Transfer your existing allowlist**
   - The allowlist format remains compatible
   - Existing allowlist entries will continue to work

### Phase 4: Update CI/CD Integration

1. **Update any CI/CD pipeline scripts**
   ```yaml
   # Before
   python secrets_scanner.py --mode strict --high-only
   
   # After
   python secrets_scanner.py --mode basic --high-only
   ```

2. **Add config file path if using custom configuration**
   ```yaml
   python secrets_scanner.py --config-file path/to/config.yaml --high-only
   ```

### Phase 5: Monitor and Refine

1. **Run the new scanner regularly and monitor results**
   - Check for any unexpected findings or missed secrets
   - Adjust patterns as needed in the configuration file

2. **Contribute improvements back to the pattern library**
   - If you develop effective new patterns, consider contributing them
   - Share feedback on false positive reduction

## Backward Compatibility

The new scanner maintains backward compatibility in several ways:

1. **Command-line arguments**: All previous arguments continue to work
2. **Mode names**: Old mode names ("strict" and "loose") are still accepted
3. **Allowlist format**: Existing allowlist files are fully compatible
4. **Integration**: Existing CI/CD integrations should require minimal changes

## Troubleshooting

### "Module not found" errors
- Ensure all new files are in the same directory

### Different findings from previous version
- Check if the findings are false positives that are now correctly ignored
- Review the configuration to ensure all necessary patterns are enabled
- Adjust pattern severity if needed

### Performance issues
- For large repositories, try scanning specific directories rather than the entire repo
- Consider using `--high-only` flag for faster CI/CD checks
- For very large repositories, you may want to split the scan into multiple runs

### Configuration parsing errors
- Validate your YAML configuration using a YAML linter
- Check for proper indentation and syntax
- Ensure all required fields are present in pattern definitions

## Example Workflow

Here's an example workflow for migrating a team's security scanning process:

1. **Development environment testing**
   - Set up the new scanner in development environment
   - Run both old and new versions in parallel
   - Compare results and adjust configuration

2. **Team review**
   - Share findings comparison with security team
   - Get feedback on any missed detections or false positives
   - Make adjustments based on feedback

3. **Pilot deployment**
   - Deploy to a single repository or project
   - Run in monitoring mode (not failing builds) initially
   - Document any issues or adjustments needed

4. **Full deployment**
   - Roll out to all repositories
   - Update documentation and training materials
   - Set up monitoring for scanner effectiveness

5. **Continuous improvement**
   - Regularly review findings and false positives
   - Update pattern configuration based on findings
   - Share patterns across teams for consistent coverage

## Pattern Migration Reference

Below is a reference for migrating specific patterns from the old format to the new format:

### Old Format
```python
# Loose Patterns
loose_patterns = [
    r"password[\"\\'=:\\s]+[A-Za-z0-9_.-]{8,}"
]

# Strict Patterns
strict_patterns = [
    r'password'
]

# Override Patterns
override_patterns = [
    r"password\s*=\s*[\"''][0-9a-zA-Z._=/-]{8,}[\"'']"
]
```

### New Format
```yaml
secret_patterns:
  password_credentials:
    - pattern: "password[\"\\'=:\\s]+(?!password|test|example|123456|admin|\\$\\{)[A-Za-z0-9_.-]{8,}"
      severity: "HIGH"
      description: "Password with 8+ characters"
      risk_type: "HARDCODED_SECRET"
      example: "password=\"mypassword123\""
      modes: ["basic", "comprehensive"]
```

Note the improvements in the new format:
- Added negative lookahead to exclude common test values
- Included metadata for better understanding
- Specified which modes the pattern applies to
- Added an example for clarity

### Mapping Severity Between Versions

The severity mapping between versions is as follows:

1. **Patterns from `override_patterns`**  
   → HIGH severity in new config

2. **Patterns from `loose_patterns`**  
   → Usually MEDIUM severity in new config  
   → HIGH if they're clearly security critical

3. **Config file patterns**  
   → Usually HIGH severity in new config  
   → MEDIUM if they're more general

4. **Logging/exposure patterns**  
   → HIGH for passwords, secrets, keys  
   → MEDIUM for more general terms

## Advanced Customization

For advanced users who need more customization:

### Creating Mode-Specific Pattern Groups

You can create pattern groups that are only used in specific modes:

```yaml
scan_modes:
  my_custom_mode:
    description: "Custom scan mode for specific projects"
    severity_filter: "MEDIUM"
    pattern_groups:
      - "api_credentials:basic"
      - "password_credentials:comprehensive"
      - "my_custom_patterns"

# Then define your custom pattern group
secret_patterns:
  my_custom_patterns:
    - pattern: "custom_pattern_regex"
      severity: "HIGH"
      # ...
```

### Extending for Different Languages or Frameworks

You can create specialized pattern groups for different languages:

```yaml
secret_patterns:
  django_patterns:
    - pattern: "SECRET_KEY\\s*=\\s*[\"'][^\"']+[\"']"
      severity: "HIGH"
      description: "Django secret key"
      modes: ["basic", "comprehensive"]
  
  rails_patterns:
    - pattern: "secret_key_base:\\s*[\"'][^\"']+[\"']"
      severity: "HIGH"
      description: "Rails secret key base"
      modes: ["basic", "comprehensive"]
```

## Further Resources

- [Full Configuration Documentation](docs/configuration.md)
- [Pattern Development Guide](docs/patterns.md)
- [CI/CD Integration Examples](docs/ci-cd.md)

## Conclusion

This migration represents a significant improvement in the maintainability and effectiveness of your secret scanning process. The new configuration-based approach makes it much easier to add, remove, and tune patterns without modifying code, resulting in more accurate detection with fewer false positives.

If you encounter any issues during migration, please file an issue on the project repository.
