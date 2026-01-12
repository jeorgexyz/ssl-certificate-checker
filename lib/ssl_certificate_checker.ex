defmodule SslCertificateChecker do
  @moduledoc """
  A robust SSL/TLS certificate checker for validating and inspecting certificates.

  This module provides functionality to check SSL certificates, validate their
  expiration dates, and extract detailed information about certificates.

  ## Examples

      iex> SslCertificateChecker.check("google.com")
      {:ok, %{
        subject: "Google LLC",
        issuer: "WR2",
        valid_from: ~U[2024-11-04 08:24:47Z],
        valid_until: ~U[2025-01-27 08:24:46Z],
        days_until_expiry: 45,
        is_valid: true,
        common_name: "*.google.com",
        san_domains: ["*.google.com", "google.com"]
      }}

      iex> SslCertificateChecker.check("invalid-host.example")
      {:error, :connection_failed}
  """

  require Logger

  @type certificate_info :: %{
          subject: String.t(),
          issuer: String.t(),
          valid_from: DateTime.t(),
          valid_until: DateTime.t(),
          days_until_expiry: integer(),
          is_valid: boolean(),
          common_name: String.t(),
          san_domains: list(String.t()),
          serial_number: String.t()
        }

  @type check_result :: {:ok, certificate_info()} | {:error, atom()}

  @default_port 443
  @warning_days 30

  @doc """
  Checks the SSL certificate for a given host and port.

  ## Parameters

    - `host` - The hostname to check (e.g., "google.com")
    - `port` - The port number (defaults to 443)
    - `opts` - Optional keyword list of options:
      - `:timeout` - Connection timeout in milliseconds (default: 10000)
      - `:verify_expiry` - Whether to verify certificate expiry (default: true)

  ## Returns

    - `{:ok, certificate_info}` - On success with certificate details
    - `{:error, reason}` - On failure with error reason

  ## Examples

      SslCertificateChecker.check("google.com")
      SslCertificateChecker.check("example.com", 8443)
      SslCertificateChecker.check("example.com", 443, timeout: 5000)
  """
  @spec check(String.t(), pos_integer(), keyword()) :: check_result()
  def check(host, port \\ @default_port, opts \\ []) do
    with :ok <- validate_host(host),
         :ok <- validate_port(port),
         {:ok, raw_output} <- fetch_certificate(host, port, opts),
         {:ok, cert_data} <- parse_certificate(raw_output),
         {:ok, enriched_data} <- enrich_certificate_data(cert_data, host, port) do
      {:ok, enriched_data}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Checks if a certificate is valid (not expired and not yet valid).

  ## Examples

      SslCertificateChecker.is_valid?("google.com")
      #=> {:ok, true}
  """
  @spec is_valid?(String.t(), pos_integer()) :: {:ok, boolean()} | {:error, atom()}
  def is_valid?(host, port \\ @default_port) do
    case check(host, port) do
      {:ok, %{is_valid: valid}} -> {:ok, valid}
      error -> error
    end
  end

  @doc """
  Gets the number of days until the certificate expires.

  Returns a negative number if already expired.

  ## Examples

      SslCertificateChecker.days_until_expiry("google.com")
      #=> {:ok, 45}
  """
  @spec days_until_expiry(String.t(), pos_integer()) :: {:ok, integer()} | {:error, atom()}
  def days_until_expiry(host, port \\ @default_port) do
    case check(host, port) do
      {:ok, %{days_until_expiry: days}} -> {:ok, days}
      error -> error
    end
  end

  @doc """
  Checks if certificate expiry is within the warning threshold (default 30 days).

  ## Examples

      SslCertificateChecker.expiring_soon?("google.com")
      #=> {:ok, false}

      SslCertificateChecker.expiring_soon?("google.com", 443, warning_days: 60)
      #=> {:ok, true}
  """
  @spec expiring_soon?(String.t(), pos_integer(), keyword()) ::
          {:ok, boolean()} | {:error, atom()}
  def expiring_soon?(host, port \\ @default_port, opts \\ []) do
    warning_days = Keyword.get(opts, :warning_days, @warning_days)

    case days_until_expiry(host, port) do
      {:ok, days} when days <= warning_days -> {:ok, true}
      {:ok, _days} -> {:ok, false}
      error -> error
    end
  end

  # Private Functions

  defp validate_host(host) when is_binary(host) and byte_size(host) > 0, do: :ok
  defp validate_host(_), do: {:error, :invalid_host}

  defp validate_port(port) when is_integer(port) and port > 0 and port <= 65535, do: :ok
  defp validate_port(_), do: {:error, :invalid_port}

  defp fetch_certificate(host, port, opts) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    command = build_openssl_command(host, port)

    task =
      Task.async(fn ->
        System.cmd("/bin/sh", ["-c", command], stderr_to_stdout: true)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task) do
      {:ok, {output, 0}} ->
        {:ok, output}

      {:ok, {error_output, _exit_code}} ->
        Logger.debug("OpenSSL command failed: #{error_output}")
        {:error, :connection_failed}

      nil ->
        {:error, :timeout}
    end
  rescue
    e ->
      Logger.error("Exception during certificate fetch: #{inspect(e)}")
      {:error, :system_error}
  end

  defp build_openssl_command(host, port) do
    """
    echo | timeout 10 openssl s_client -showcerts -servername #{host} -connect #{host}:#{port} 2>/dev/null | \
    openssl x509 -inform pem -noout -issuer -subject -dates -serial -ext subjectAltName
    """
    |> String.replace("\n", " ")
    |> String.trim()
  end

  defp parse_certificate(output) do
    lines = String.split(output, "\n", trim: true)

    parsed_data =
      lines
      |> Enum.reduce(%{}, fn line, acc ->
        parse_line(line, acc)
      end)

    if map_size(parsed_data) > 0 do
      {:ok, parsed_data}
    else
      {:error, :invalid_certificate_data}
    end
  end

  defp parse_line(line, acc) do
    cond do
      String.starts_with?(line, "notBefore=") ->
        Map.put(acc, :not_before, String.replace_prefix(line, "notBefore=", ""))

      String.starts_with?(line, "notAfter=") ->
        Map.put(acc, :not_after, String.replace_prefix(line, "notAfter=", ""))

      String.starts_with?(line, "subject=") ->
        subject = String.replace_prefix(line, "subject=", "")
        Map.put(acc, :subject, parse_distinguished_name(subject))

      String.starts_with?(line, "issuer=") ->
        issuer = String.replace_prefix(line, "issuer=", "")
        Map.put(acc, :issuer, parse_distinguished_name(issuer))

      String.starts_with?(line, "serial=") ->
        Map.put(acc, :serial, String.replace_prefix(line, "serial=", ""))

      String.contains?(line, "DNS:") ->
        domains = parse_san_domains(line)
        Map.put(acc, :san_domains, domains)

      true ->
        acc
    end
  end

  defp parse_distinguished_name(dn_string) do
    # Extract organization (O=) or common name (CN=)
    cond do
      org = Regex.run(~r/O\s*=\s*([^,\/]+)/, dn_string) ->
        Enum.at(org, 1) |> String.trim()

      cn = Regex.run(~r/CN\s*=\s*([^,\/]+)/, dn_string) ->
        Enum.at(cn, 1) |> String.trim()

      true ->
        dn_string
    end
  end

  defp parse_san_domains(line) do
    ~r/DNS:([^,\s]+)/
    |> Regex.scan(line)
    |> Enum.map(fn [_, domain] -> domain end)
  end

  defp enrich_certificate_data(cert_data, _host, _port) do
    with {:ok, valid_from} <- parse_date(cert_data[:not_before]),
         {:ok, valid_until} <- parse_date(cert_data[:not_after]) do
      now = DateTime.utc_now()
      days_until_expiry = DateTime.diff(valid_until, now, :day)
      is_valid = DateTime.compare(now, valid_from) != :lt and DateTime.compare(now, valid_until) == :lt

      enriched = %{
        subject: cert_data[:subject] || "",
        issuer: cert_data[:issuer] || "",
        valid_from: valid_from,
        valid_until: valid_until,
        days_until_expiry: days_until_expiry,
        is_valid: is_valid,
        common_name: extract_common_name(cert_data[:subject]),
        san_domains: cert_data[:san_domains] || [],
        serial_number: cert_data[:serial] || ""
      }

      {:ok, enriched}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_date(nil), do: {:error, :missing_date}

  defp parse_date(date_string) do
    # OpenSSL date format: "Nov  4 08:24:47 2024 GMT" or "Dec 31 23:59:59 2024 GMT"
    # We'll use a simpler parsing approach without external dependencies
    
    month_map = %{
      "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
      "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
      "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12
    }

    # Parse format like "Nov  4 08:24:47 2024 GMT"
    regex = ~r/(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)/
    
    case Regex.run(regex, date_string) do
      [_, month_str, day, hour, minute, second, year] ->
        with month when not is_nil(month) <- Map.get(month_map, month_str),
             {:ok, datetime} <- DateTime.new(
               Date.from_erl!({String.to_integer(year), month, String.to_integer(day)}),
               Time.from_erl!({String.to_integer(hour), String.to_integer(minute), String.to_integer(second)})
             ) do
          {:ok, datetime}
        else
          _ -> {:error, :invalid_date_format}
        end
      
      _ ->
        {:error, :invalid_date_format}
    end
  rescue
    _ -> {:error, :date_parse_error}
  end

  defp extract_common_name(nil), do: ""

  defp extract_common_name(subject) do
    case Regex.run(~r/CN\s*=\s*([^,\/]+)/, subject) do
      [_, cn] -> String.trim(cn)
      _ -> subject
    end
  end
end
