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
  common_name: "*.google.com",
  days_until_expiry: 45,
  is_valid: true,
  issuer: "WR2",
  san_domains: ["*.google.com", "google.com"],
  serial_number: "ABC123...",
  subject: "Google LLC",
  valid_from: ~U[2024-11-04 08:24:47Z],
  valid_until: ~U[2025-01-27 08:24:46Z]
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
    IO.puts("[ERROR] #{reason}")
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
    IO.puts("[ERROR] #{reason}")
end)
```

## Using the CLI

```bash
# Build the escript
mix escript.build

# Check a certificate
./ssl-certificate-checker google.com

# Check with custom port
./ssl-certificate-checker mysite.com 8443

# Get JSON output
./ssl-certificate-checker google.com --json

# Use in scripts
if ./ssl-certificate-checker mysite.com; then
  echo "Certificate is valid"
else
  echo "Certificate check failed"
fi
```

## Using with Docker

```bash
# Build the image
docker build -t ssl-checker .

# Run a check
docker run ssl-checker google.com

# Get JSON output
docker run ssl-checker "SslCertificateChecker.CLI.main([\"google.com\", \"--json\"])"
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
        Logger.error("Failed to check #{host}: #{reason}")
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
  IO.puts("[ERROR] #{host}: #{reason}")
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

### "OpenSSL not found"
```bash
# On Ubuntu/Debian
sudo apt-get install openssl

# On macOS
brew install openssl

# On Alpine (Docker)
apk add --no-cache openssl
```

### "Connection timeout"
```elixir
# Increase timeout
SslCertificateChecker.check("slow-site.com", 443, timeout: 30_000)
```

### "Invalid certificate data"
This usually means the host doesn't have a valid SSL certificate or isn't reachable. Verify:
1. The host is accessible
2. The port is correct (usually 443)
3. The host actually uses SSL/TLS

## Getting Help

- Read the [README](README.md)
- [Open an issue](https://github.com/jeorgexyz/ssl-certificate-checker/issues)
- Check existing issues for solutions
- Contact the maintainer

Happy certificate checking!
