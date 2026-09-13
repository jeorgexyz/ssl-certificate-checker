# Quick Start Guide

Get up and running with SSL Certificate Checker in 5 minutes!

## Installation

```bash
# Clone the repository
git clone https://github.com/jeorgexyz/ssl-certificate-checker.git
cd ssl-certificate-checker

# Install dependencies
mix deps.get

# Run tests to verify installation
mix test
```

## Your First Certificate Check

Open `iex` in your project:

```bash
iex -S mix
```

Then try:

```elixir
# Check a certificate
{:ok, cert} = SslCertificateChecker.check("google.com")

# View the results
IO.inspect(cert, pretty: true)
```

Output:
```elixir
%{
  cipher_suite: "TLS_AES_256_GCM_SHA384",
  common_name: "*.google.com",
  days_until_expiry: 49,
  is_valid: true,
  issuer: "Google Trust Services",
  key_size: 256,
  key_type: "EC",
  san_domains: ["*.google.com", "*.appengine.google.com", ...],
  serial_number: "10C2A4E9E146487D0A329F6E9CD50813",
  signature_algorithm: "ecdsa-with-SHA256",
  subject: "*.google.com",
  tls_version: "TLSv1.3",
  valid_from: ~U[2026-08-10 08:37:42Z],
  valid_until: ~U[2026-11-02 08:37:41Z],
  verification_errors: []
}
```

## Common Use Cases

### 1. Check if a Certificate is Valid

```elixir
case SslCertificateChecker.is_valid?("mysite.com") do
  {:ok, true} ->
    IO.puts("[OK] Certificate is valid")

  {:ok, false} ->
    IO.puts("[WARN] Certificate is invalid or expired")

  {:error, reason} ->
    IO.puts("[ERROR] #{inspect(reason)}")
end

```

### 2. Get Days Until Expiry

```elixir
{:ok, days} = SslCertificateChecker.days_until_expiry("mysite.com")
IO.puts("Certificate expires in #{days} days")
```

### 3. Check for Expiring Certificates

```elixir
# Check if certificate expires within 30 days
{:ok, expiring?} = SslCertificateChecker.expiring_soon?("mysite.com")

if expiring? do
  IO.puts("[WARN] Certificate is expiring soon")
end

```

### 4. Monitor Multiple Sites

```elixir
sites = ["google.com", "github.com", "stackoverflow.com"]

results = 
  sites
  |> Task.async_stream(fn site ->
    SslCertificateChecker.check(site)
  end)
  |> Enum.map(fn {:ok, result} -> result end)

# Process results
Enum.each(results, fn
  {:ok, cert} ->
    IO.puts("[OK] #{cert.common_name}: #{cert.days_until_expiry} days")

  {:error, reason} ->
    IO.puts("[ERROR] #{inspect(reason)}")
end)
```

## Using the CLI

```bash
# Build the escript
MIX_ENV=prod mix escript.build

# Check a certificate (on Windows: escript ssl_certificate_checker google.com)
./ssl_certificate_checker google.com

# Check with custom port
./ssl_certificate_checker mysite.com 8443

# Get JSON output
./ssl_certificate_checker google.com --json

# Use in scripts: exit code 0 = valid, 1 = check failed, 2 = invalid certificate
if ./ssl_certificate_checker mysite.com; then
  echo "Certificate is valid"
else
  echo "Certificate check failed"
fi

# Pull out one field with jq
./ssl_certificate_checker mysite.com --json | jq .days_until_expiry
```

## Using with Docker

```bash
# Build the image
docker build -t ssl-certificate-checker .

# Run a check
docker run --rm ssl-certificate-checker google.com

# Get JSON output
docker run --rm ssl-certificate-checker google.com --json
```

## Integration Examples

### Phoenix Application

```elixir
defmodule MyApp.CertMonitor do
  use GenServer
  require Logger

  def start_link(hosts) do
    GenServer.start_link(__MODULE__, hosts, name: __MODULE__)
  end

  def init(hosts) do
    schedule_check()
    {:ok, %{hosts: hosts}}
  end

  def handle_info(:check_certificates, state) do
    Enum.each(state.hosts, &check_and_alert/1)
    schedule_check()
    {:noreply, state}
  end

  defp check_and_alert(host) do
    case SslCertificateChecker.expiring_soon?(host, 443, warning_days: 30) do
      {:ok, true} ->
        Logger.warning("Certificate for #{host} is expiring soon!")
        send_alert(host)
      {:ok, false} ->
        Logger.debug("Certificate for #{host} is OK")
      {:error, reason} ->
        Logger.error("Failed to check #{host}: #{inspect(reason)}")
    end
  end

  defp schedule_check do
    Process.send_after(self(), :check_certificates, :timer.hours(24))
  end

  defp send_alert(host) do
    # Send email, Slack notification, etc.
  end
end
```

### Scheduled Job with Quantum

```elixir
# In config/config.exs
config :my_app, MyApp.Scheduler,
  jobs: [
    {"0 0 * * *", {MyApp.CertChecker, :check_all, []}}
  ]

# In lib/my_app/cert_checker.ex
defmodule MyApp.CertChecker do
  def check_all do
    hosts = Application.get_env(:my_app, :monitored_hosts)
    
    hosts
    |> Task.async_stream(&check_host/1, max_concurrency: 10)
    |> Enum.each(fn {:ok, result} -> handle_result(result) end)
  end

  defp check_host(host) do
    case SslCertificateChecker.check(host) do
      {:ok, cert} when cert.days_until_expiry <= 30 ->
        {:warning, host, cert.days_until_expiry}
      {:ok, _cert} ->
        {:ok, host}
      {:error, reason} ->
        {:error, host, reason}
    end
  end

defp handle_result({:warning, host, days}) do
  # Send notification
  IO.puts("[WARN] #{host} expires in #{days} days")
end

defp handle_result({:ok, host}) do
  # All good
  IO.puts("[OK] #{host} is OK")
end

defp handle_result({:error, host, reason}) do
  # Log error
  IO.puts("[ERROR] #{host}: #{inspect(reason)}")
end

```

## Testing Your Code

```elixir
# In your test file
defmodule MyCertCheckerTest do
  use ExUnit.Case
  
  test "checks certificate validity" do
    case SslCertificateChecker.check("google.com") do
      {:ok, cert} ->
        assert cert.is_valid == true
        assert cert.days_until_expiry > 0
      {:error, _reason} ->
        # Skip test if network unavailable
        :ok
    end
  end
end
```

## Next Steps

1. **Read the full documentation**: Check out the comprehensive [README.md](README.md)
2. **Explore examples**: See [examples/usage_examples.exs](examples/usage_examples.exs)
3. **Review the API**: Read the inline documentation with `mix docs` and open `doc/index.html`
4. **Understand improvements**: Check [IMPROVEMENTS.md](IMPROVEMENTS.md) for details on what's new
5. **Stay updated**: Review [CHANGELOG.md](CHANGELOG.md) for version history

## Troubleshooting

### `{:error, :no_trusted_certificates}`
The operating system's CA store couldn't be loaded. This needs Erlang/OTP 25+, and on
minimal Linux images the CA bundle must be installed:
```bash
# On Ubuntu/Debian
sudo apt-get install ca-certificates

# On Alpine (Docker)
apk add --no-cache ca-certificates
```
For servers using a private CA, pass it explicitly with `cacerts: [ca_der]`.

### Certificate is returned but `is_valid` is `false`
Check `cert.verification_errors`, e.g. `:unknown_ca` (untrusted chain), `:selfsigned_peer`,
`:hostname_check_failed`, or `:cert_expired`.

### "Connection timeout"
```elixir
# Increase timeout
SslCertificateChecker.check("slow-site.com", 443, timeout: 30_000)
```

### `:connection_refused`, `:nxdomain`, or `{:tls_handshake_failed, _}`
The host couldn't be reached over TLS. Verify:
1. The host name resolves and is accessible
2. The port is correct (usually 443)
3. The service on that port actually speaks TLS 1.2 or 1.3

## Getting Help

- Read the [README](README.md)
- [Open an issue](https://github.com/jeorgexyz/ssl-certificate-checker/issues)
- Check existing issues for solutions
- Contact the maintainer

Happy certificate checking!
