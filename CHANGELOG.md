# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-09

### Added
- Complete rewrite with comprehensive improvements
- Type specifications (@spec) for all public functions
- Comprehensive error handling with meaningful error atoms
- CLI interface for command-line usage
- Support for Subject Alternative Names (SAN) extraction
- Certificate serial number extraction
- Timeout configuration for certificate fetching
- `is_valid?/2` - Check if certificate is currently valid
- `days_until_expiry/2` - Get days until certificate expires
- `expiring_soon?/3` - Check if certificate is expiring within threshold
- Async/await support with Task-based timeout handling
- Comprehensive test suite with real-world examples
- Docker support with multi-stage builds
- GitHub Actions CI/CD workflow
- ExDoc documentation generation
- Credo for code quality
- Dialyzer for type checking
- Code coverage with ExCoveralls
- Detailed README with usage examples
- MIT License
- Example scripts demonstrating various use cases
- Configuration files for dev/test/prod environments

### Changed
- Improved OpenSSL command to include `-servername` for SNI support
- Better date parsing without external dependencies
- Structured error handling with `{:ok, result}` and `{:error, reason}` tuples
- Enhanced certificate parsing with more robust regex patterns
- Upgraded to return rich certificate info maps instead of basic strings
- Better logging with configurable log levels
- Improved module documentation with examples

### Fixed
- Proper error handling for network failures
- Correct parsing of distinguished names (DN)
- Timeout handling to prevent hanging connections
- Better handling of missing certificate fields
- Proper validation of host and port parameters

### Security
- Added timeout protection against slow/hanging connections
- Better input validation for hosts and ports
- No shell injection vulnerabilities in OpenSSL commands

## [0.1.0] - Initial Release

### Added
- Basic SSL certificate checking functionality
- Simple certificate information extraction
- OpenSSL integration
- Basic error handling

### Known Issues
- Limited error handling
- No type specifications
- Basic string output instead of structured data
- No timeout protection
- Limited certificate information extraction
- Typo in openssl command (`-shocerts` instead of `-showcerts`)
