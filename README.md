# SSL Certificate Checker

A robust Elixir library for checking and validating SSL/TLS certificates. Get detailed certificate information, expiry warnings, and comprehensive validation with a simple, elegant API.

[![Hex.pm](https://img.shields.io/hexpm/v/ssl_certificate_checker.svg)](https://hex.pm/packages/ssl_certificate_checker)
[![Documentation](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/ssl_certificate_checker)

## Features

- **Certificate Validation** - Check if certificates are valid and properly configured
- **Expiry Monitoring** - Get precise expiry dates and warnings
- **Detailed Information** - Extract subject, issuer, SAN domains, and more
- **Async Support** - Built with async operations and timeouts
- **Error Handling** - Comprehensive error handling with meaningful messages
- **Type Safe** - Full type specifications for better code quality
- **CLI Tool** - Command-line interface for quick checks
- **Zero External Dependencies** - Uses only standard Elixir libraries (except Jason for JSON)

## Installation

Add `ssl_certificate_checker` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ssl_certificate_checker, "~> 0.2.0"}
  ]
end
```

Then run:

```bash
mix deps.get
```

## Quick Start

```elixir
# Check a certificate
{:ok, cert} = SslCertificateChecker.check("google.com")

# Check certificate validity
{:ok, valid?} = SslCertificateChecker.is_valid?("google.com")

# Get days until expiry
{:ok, days} = SslCertificateChecker.days_until_expiry("google.com")

# Check if expiring soon (within 30 days)
{:ok, expiring?} = SslCertificateChecker.expiring_soon?("google.com")
```

## Usage Examples

### Basic Certificate Check

```elixir
case SslCertificateChecker.check("google.com") do
  {:ok, cert_info} ->
    IO.puts("Subject: #{cert_info.subject}")
    IO.puts("Issuer: #{cert_info.issuer}")
    IO.puts("Valid until: #{cert_info.valid_until}")
    IO.puts("Days until expiry: #{cert_info.days_until_expiry}")
    IO.puts("Is valid: #{cert_info.is_valid}")

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end
```

### Custom Port

```elixir
# Check certificate on a custom port
{:ok, cert} = SslCertificateChecker.check("example.com", 8443)
```

### With Timeout

```elixir
# Set a custom timeout (in milliseconds)
{:ok, cert} = SslCertificateChecker.check("example.com", 443, timeout: 5000)
```

### Monitoring Certificate Expiry

```elixir
defmodule CertMonitor do
  def check_certificates(hosts) do
    hosts
    |> Enum.map(fn host ->
      case SslCertificateChecker.check(host) do
        {:ok, cert} ->
          %{
            host: host,
            days_remaining: cert.days_until_expiry,
            status: cert_status(cert)
          }

        {:error, reason} ->
          %{host: host, error: reason}
      end
    end)
  end

  defp cert_status(cert) do
    cond do
      not cert.is_valid -> :invalid
      cert.days_until_expiry < 0 -> :expired
      cert.days_until_expiry <= 7 -> :critical
      cert.days_until_expiry <= 30 -> :warning
      true -> :ok
    end
  end
end

# Usage
hosts = ["google.com", "github.com", "example.com"]
results = CertMonitor.check_certificates(hosts)
```

### Checking Multiple Hosts Concurrently

```elixir
hosts = ["google.com", "github.com", "stackoverflow.com"]

results =
  hosts
  |> Task.async_stream(
    fn host ->
      case SslCertificateChecker.check(host) do
        {:ok, cert} -> {host, :ok, cert.days_until_expiry}
        {:error, reason} -> {host, :error, reason}
      end
    end,
    timeout: 10_000,
    max_concurrency: 10
  )
  |> Enum.map(fn {:ok, result} -> result end)

Enum.each(results, fn
{host, :ok, days} ->
  IO.puts("#{host}: #{days} days until expiry")

{host, :error, reason} ->
  IO.puts("#{host}: error - #{reason}")

end)
```

## API Reference

### Main Functions

#### `check(host, port \\ 443, opts \\ [])`

Checks the SSL certificate for a given host and port.

**Returns:**
- `{:ok, certificate_info}` - Success with certificate details
- `{:error, reason}` - Failure with error reason

**Certificate Info Map:**
```elixir
%{
  subject: "Organization Name",
  issuer: "Certificate Authority",
  valid_from: ~U[2024-01-01 00:00:00Z],
  valid_until: ~U[2025-01-01 00:00:00Z],
  days_until_expiry: 45,
  is_valid: true,
  common_name: "*.example.com",
  san_domains: ["*.example.com", "example.com"],
  serial_number: "ABC123..."
}
```

#### `is_valid?(host, port \\ 443)`

Checks if a certificate is currently valid.

**Returns:**
- `{:ok, true}` - Certificate is valid
- `{:ok, false}` - Certificate is invalid or expired
- `{:error, reason}` - Error occurred

#### `days_until_expiry(host, port \\ 443)`

Gets the number of days until the certificate expires.

**Returns:**
- `{:ok, days}` - Number of days (negative if expired)
- `{:error, reason}` - Error occurred

#### `expiring_soon?(host, port \\ 443, opts \\ [])`

Checks if certificate expiry is within the warning threshold.

**Options:**
- `:warning_days` - Days threshold (default: 30)

**Returns:**
- `{:ok, true}` - Certificate is expiring soon
- `{:ok, false}` - Certificate is not expiring soon
- `{:error, reason}` - Error occurred

## Command Line Interface

### Installation as Escript

```bash
mix escript.build
./ssl_certificate_checker google.com
```

### Usage

```bash
# Basic check
ssl_certificate_checker google.com

# Custom port
ssl_certificate_checker example.com 8443

# JSON output
ssl_certificate_checker google.com --json

# Verbose mode
ssl_certificate_checker google.com --verbose
```

### Exit Codes

- `0` - Certificate is valid
- `1` - Error occurred during check
- `2` - Certificate is invalid or expired

## Error Handling

The library returns standardized error atoms:

- `:invalid_host` - Invalid or empty hostname
- `:invalid_port` - Invalid port number
- `:connection_failed` - Failed to connect to host
- `:timeout` - Operation timed out
- `:system_error` - System-level error
- `:invalid_certificate_data` - Could not parse certificate
- `:missing_date` - Certificate dates missing
- `:invalid_date_format` - Could not parse date
- `:date_parse_error` - Error parsing date

```elixir
case SslCertificateChecker.check("invalid-host") do
  {:ok, cert} ->
    # Handle success

  {:error, :invalid_host} ->
    IO.puts("Invalid hostname provided")

  {:error, :connection_failed} ->
    IO.puts("Could not connect to host")

  {:error, :timeout} ->
    IO.puts("Connection timed out")

  {:error, reason} ->
    IO.puts("Unexpected error: #{reason}")
end
```

## Docker Support

Build and run with Docker:

```dockerfile
FROM elixir:1.14-alpine

RUN apk add --no-cache openssl

WORKDIR /app
COPY . .

RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix deps.get && \
    mix compile

CMD ["mix", "run", "-e", "SslCertificateChecker.CLI.main(System.argv())"]
```

```bash
docker build -t ssl-checker .
docker run ssl-checker google.com
```

## Requirements

- Elixir ~> 1.14
- OpenSSL (available in system PATH)
- Erlang/OTP 24+

## Testing

```bash
# Run tests
mix test

# Run with coverage
mix coveralls

# Run with coverage HTML report
mix coveralls.html

# Run linter
mix credo

# Run type checker
mix dialyzer
```

## Development

```bash
# Get dependencies
mix deps.get

# Run tests
mix test

# Generate documentation
mix docs

# Format code
mix format
```

## Performance

The library is designed for efficiency:

- Async operations with configurable timeouts
- No heavy dependencies
- Efficient parsing
- Concurrent checking support

Typical check takes 100-500ms depending on network latency.

## Security Considerations

- This library checks certificate validity but does not perform full chain validation
- Always validate certificates in production environments
- Use appropriate timeouts to prevent hanging connections
- Consider rate limiting when checking multiple hosts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with ❤️ using Elixir
- Uses OpenSSL for certificate inspection
- Inspired by the need for simple certificate monitoring

## Changelog

### v0.2.0
- Complete rewrite with improved error handling
- Added comprehensive type specifications
- Added CLI interface
- Improved certificate parsing
- Added SAN domain extraction
- Better timeout handling
- Comprehensive test suite

### v0.1.0
- Initial release
- Basic certificate checking
