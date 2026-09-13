defmodule SslCertificateChecker.CLI do
  @moduledoc """
  Command-line interface for SSL Certificate Checker.

  Build the executable with `mix escript.build`, then run
  `./ssl_certificate_checker --help` for usage.

  With `--json`, stdout contains exactly one JSON object for both successful checks and
  failures, so output can be piped straight into other tools. Exit codes:

    * `0` - the certificate is valid
    * `1` - the check could not be completed (invalid arguments, network or TLS error)
    * `2` - a certificate was retrieved but failed verification
  """

  @exit_ok 0
  @exit_error 1
  @exit_invalid 2

  @default_port 443
  @max_listed_san_domains 10

  @switches [json: :boolean, timeout: :integer, cacert: :keep, help: :boolean]
  @aliases [h: :help]

  @doc """
  Escript entry point. Runs the CLI and halts with its exit code.
  """
  @spec main([String.t()]) :: no_return()
  def main(args) do
    args |> run() |> System.halt()
  end

  @doc """
  Runs the CLI with `args`, writing to stdout and stderr, and returns the exit code.
  """
  @spec run([String.t()]) :: 0 | 1 | 2
  def run(args) do
    case parse_args(args) do
      :help ->
        IO.puts(usage())
        @exit_ok

      {:ok, config} ->
        run_check(config)

      {:error, message} ->
        IO.puts(:stderr, "Error: #{message}\n")
        IO.puts(:stderr, usage())
        @exit_error
    end
  end

  # Argument parsing

  defp parse_args(args) do
    case OptionParser.parse(args, strict: @switches, aliases: @aliases) do
      {opts, positional, []} ->
        if opts[:help], do: :help, else: build_config(opts, positional)

      {_opts, _positional, [{switch, nil} | _]} ->
        {:error, "Unknown option #{switch}"}

      {_opts, _positional, [{switch, value} | _]} ->
        {:error, "Invalid value for #{switch}: #{value}"}
    end
  end

  defp build_config(opts, positional) do
    with {:ok, host, port} <- parse_positional(positional),
         {:ok, check_opts} <- check_options(opts) do
      {:ok,
       %{host: host, port: port, json: Keyword.get(opts, :json, false), check_opts: check_opts}}
    end
  end

  defp parse_positional([]), do: {:error, "Missing host"}
  defp parse_positional([host]), do: {:ok, host, @default_port}

  defp parse_positional([host, port]) do
    case Integer.parse(port) do
      {port, ""} -> {:ok, host, port}
      _ -> {:error, "Invalid port: #{port}"}
    end
  end

  defp parse_positional(_args), do: {:error, "Too many arguments"}

  defp check_options(opts) do
    with {:ok, timeout_opts} <- timeout_option(opts[:timeout]),
         {:ok, cacert_opts} <- cacert_option(Keyword.get_values(opts, :cacert)) do
      {:ok, timeout_opts ++ cacert_opts}
    end
  end

  defp timeout_option(nil), do: {:ok, []}
  defp timeout_option(ms) when ms > 0, do: {:ok, [timeout: ms]}
  defp timeout_option(ms), do: {:error, "Invalid timeout: #{ms}"}

  defp cacert_option([]), do: {:ok, []}

  defp cacert_option(paths) do
    Enum.reduce_while(paths, {:ok, [cacerts: []]}, fn path, {:ok, [cacerts: cacerts]} ->
      case read_certificates(path) do
        {:ok, ders} -> {:cont, {:ok, [cacerts: cacerts ++ ders]}}
        {:error, message} -> {:halt, {:error, message}}
      end
    end)
  end

  defp read_certificates(path) do
    with {:ok, pem} <- File.read(path),
         [_ | _] = ders <-
           for({:Certificate, der, :not_encrypted} <- :public_key.pem_decode(pem), do: der) do
      {:ok, ders}
    else
      [] -> {:error, "No PEM certificates found in #{path}"}
      {:error, reason} -> {:error, "Cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  # Checking and output

  defp run_check(%{host: host, port: port, json: json?, check_opts: check_opts}) do
    unless json?, do: IO.puts("Checking TLS certificate for #{host}:#{port}...\n")

    result = SslCertificateChecker.check(host, port, check_opts)

    if json?, do: print_json(result, host, port), else: print_text(result, host, port)

    exit_code(result)
  end

  defp exit_code({:ok, %{is_valid: true}}), do: @exit_ok
  defp exit_code({:ok, _cert}), do: @exit_invalid
  defp exit_code({:error, _reason}), do: @exit_error

  defp print_json({:ok, cert}, host, port) do
    cert
    |> Map.merge(%{host: host, port: port})
    |> encode_json()
  end

  defp print_json({:error, reason}, host, port) do
    encode_json(%{
      host: host,
      port: port,
      error: error_code(reason),
      message: describe_error(reason)
    })
  end

  defp encode_json(data), do: data |> Jason.encode!(pretty: true) |> IO.puts()

  defp print_text({:ok, cert}, host, port), do: display_certificate(cert, host, port)

  defp print_text({:error, reason}, _host, _port),
    do: IO.puts(:stderr, "Error: #{describe_error(reason)}")

  defp display_certificate(cert, host, port) do
    IO.puts("SSL Certificate Information")
    IO.puts(String.duplicate("=", 60))
    IO.puts("Host:              #{host}:#{port}")
    IO.puts("Common Name:       #{cert.common_name}")
    IO.puts("Subject:           #{cert.subject}")
    IO.puts("Issuer:            #{cert.issuer}")
    IO.puts("Serial Number:     #{cert.serial_number}")
    IO.puts("")
    IO.puts("Valid From:        #{DateTime.to_string(cert.valid_from)}")
    IO.puts("Valid Until:       #{DateTime.to_string(cert.valid_until)}")
    IO.puts("")
    IO.puts("TLS:               #{cert.tls_version} (#{cert.cipher_suite})")
    IO.puts("Key:               #{format_key(cert)}")
    IO.puts("Signature:         #{cert.signature_algorithm}")
    IO.puts("")
    IO.puts("Status:            #{if cert.is_valid, do: "Valid", else: "INVALID"}")

    Enum.each(cert.verification_errors, fn error ->
      IO.puts("  - #{describe_verification_error(error)}")
    end)

    IO.puts("Expiry:            #{describe_expiry(cert.days_until_expiry)}")

    unless Enum.empty?(cert.san_domains) do
      {listed, unlisted} = Enum.split(cert.san_domains, @max_listed_san_domains)

      IO.puts("")
      IO.puts("Subject Alternative Names:")
      Enum.each(listed, &IO.puts("  - #{&1}"))

      if unlisted != [] do
        IO.puts("  ... and #{length(unlisted)} more (use --json to list all)")
      end
    end

    IO.puts("")
  end

  defp describe_expiry(days) when days < 0, do: "EXPIRED #{abs(days)} days ago"
  defp describe_expiry(days) when days <= 7, do: "CRITICAL: expires in #{days} days"
  defp describe_expiry(days) when days <= 30, do: "WARNING: expires in #{days} days"
  defp describe_expiry(days), do: "OK: expires in #{days} days"

  defp format_key(%{key_type: type, key_size: nil}), do: type
  defp format_key(%{key_type: type, key_size: size}), do: "#{type} #{size}-bit"

  defp describe_verification_error(:unknown_ca), do: "Certificate chain is not trusted"
  defp describe_verification_error(:selfsigned_peer), do: "Certificate is self-signed"

  defp describe_verification_error(:hostname_check_failed),
    do: "Certificate does not match the host name"

  defp describe_verification_error(:cert_expired),
    do: "Certificate is expired or not yet valid"

  defp describe_verification_error(error), do: "Verification failed: #{error}"

  defp error_code({code, _detail}), do: code
  defp error_code(code), do: code

  defp describe_error(:invalid_host), do: "Not a valid hostname or IP address"
  defp describe_error(:invalid_port), do: "Port must be between 1 and 65535"
  defp describe_error(:no_trusted_certificates), do: "No trusted CA certificates are available"
  defp describe_error(:timeout), do: "Timed out connecting or completing the TLS handshake"
  defp describe_error(:nxdomain), do: "Host name does not resolve"
  defp describe_error(:connection_refused), do: "Connection refused"
  defp describe_error(:invalid_certificate), do: "The server's certificate could not be decoded"
  defp describe_error({:connection_failed, reason}), do: "Connection failed: #{reason}"

  defp describe_error({:tls_handshake_failed, message}),
    do: "TLS handshake failed: #{String.trim(message)}"

  defp usage do
    """
    Usage: ssl_certificate_checker <host> [port] [options]

    Checks the TLS certificate presented by <host> (port 443 by default): trusted chain,
    host name match, and validity period.

    Options:
      --json            Print a single JSON object, for results and errors alike
      --timeout <ms>    Connection and handshake timeout (default: 10000)
      --cacert <file>   Trust the CA certificates in a PEM file instead of the
                        system store; may be repeated
      -h, --help        Show this help

    Examples:
      ssl_certificate_checker google.com
      ssl_certificate_checker example.com 8443 --json
      ssl_certificate_checker internal.example --cacert internal-ca.pem

    Exit codes:
      0  Certificate is valid
      1  Check could not be completed (invalid arguments, network or TLS error)
      2  Certificate was retrieved but failed verification
    """
  end
end
