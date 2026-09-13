# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Fixed shell command injection: host names were interpolated into a `/bin/sh -c` command,
  so a host such as `"example.com; <command>"` executed arbitrary commands. Certificates are
  now fetched with Erlang's `:ssl` and no shell is involved. The 0.2.0 note below claiming
  "no shell injection vulnerabilities" was incorrect.
- Host names are now validated strictly (DNS hostname or IP literal only).

### Changed
- **Breaking:** `is_valid` now requires a trusted chain and a matching host name in addition to
  the validity period. Previously self-signed certificates and certificates for other domains
  were reported as valid.
- **Breaking:** error reasons are now `:nxdomain`, `:connection_refused`, `:timeout`,
  `{:connection_failed, posix}`, `{:tls_handshake_failed, message}`, `:invalid_certificate`, and
  `:no_trusted_certificates`. `:connection_failed`, `:system_error`,
  `:invalid_certificate_data`, `:missing_date`, `:invalid_date_format`, and `:date_parse_error`
  are gone.
- OpenSSL is no longer required; Erlang/OTP 25+ is.
- `days_until_expiry` rounds down, so a certificate that expired hours ago is `-1`, not `0`.
- `subject` and `issuer` prefer the organization (O) and fall back to the common name (CN);
  `common_name` is now always the subject's CN.
- Tests run offline against local TLS servers; tests that use public hosts are tagged
  `:external` and excluded by default.
- **Breaking (CLI):** with `--json`, stdout now contains exactly one JSON object, including
  `host` and `port`, and failures are reported as `{"error": ..., "message": ...}` instead of
  plain text. The "Checking..." line is no longer printed in JSON mode.
- **Breaking (CLI):** `--verbose` was removed (it had no effect), and running without a host
  now exits with code 1 instead of 0.
- The CLI lists at most 10 subject alternative names in text mode; `--json` includes all.
- Logs go to stderr so they can't corrupt JSON output.
- `mix.lock` is now committed so CI, Docker, and escript builds are reproducible.
- CI uses `actions/checkout@v4` and `actions/cache@v4`, and builds the escript and Docker image.

### Added
- `verification_errors`, `signature_algorithm`, `key_type`, `key_size`, `tls_version`, and
  `cipher_suite` fields.
- `:cacerts` option for servers issued by a private CA.
- `is_valid?/3`, `days_until_expiry/3`, and `expiring_soon?/3` now pass options such as
  `:timeout` through to `check/3`.
- Windows and macOS support.
- `mix escript.build` produces a working `ssl_certificate_checker` executable.
- CLI options `--timeout <ms>` and `--cacert <file>`.
- `SslCertificateChecker.CLI.run/1`, which returns the exit code instead of halting.
- The Docker image is built from the escript on a minimal Erlang base and runs as `nobody`.

### Fixed
- Certificates whose chain includes a cross-signed root were reported as `:unknown_ca` whenever
  the cross-signing root wasn't in the trust store, even though a trusted path existed (for
  example google.com on Alpine Linux). OTP's search for alternative paths now runs as it does
  for any normal TLS client.
- `ssl_certificate_checker <host> --json` failed with "Invalid port" unless a port was also given.
- The Docker build failed because `mix.lock` was not in the repository.
- The project did not compile: invalid app name in `mix.exs` and an undefined variable in the CLI.
- The `:verify_expiry` option was documented but never implemented; it has been removed.
- A timed-out check could leave an `openssl` process running.
- Removed the Dialyzer `:race_conditions` flag, which newer OTP releases reject.

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
