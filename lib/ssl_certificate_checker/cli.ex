defmodule SslCertificateChecker.CLI do
  @moduledoc """
  Command-line interface for SSL Certificate Checker.

  ## Usage

      mix run -e "SslCertificateChecker.CLI.main([\"google.com\"])"
      mix run -e "SslCertificateChecker.CLI.main([\"example.com\", \"8443\"])"
  """

  @doc """
  Main entry point for the CLI.
  """
  def main(args) do
    case parse_args(args) do
      {:ok, host, port, opts} ->
        check_and_display(host, port, opts)

      {:error, :help} ->
        print_help()

      {:error, reason} ->
        IO.puts(:stderr, "Error: #{reason}")
        print_help()
        System.halt(1)
    end
  end

  defp parse_args(["--help"]), do: {:error, :help}
  defp parse_args(["-h"]), do: {:error, :help}
  defp parse_args([]), do: {:error, :help}

  defp parse_args([host]) do
    {:ok, host, 443, []}
  end

  defp parse_args([host, port_str]) do
    case Integer.parse(port_str) do
      {port, ""} -> {:ok, host, port, []}
      _ -> {:error, "Invalid port number: #{port_str}"}
    end
  end

  defp parse_args([host, port_str | opts]) do
    case Integer.parse(port_str) do
      {port, ""} -> {:ok, host, port, parse_opts(opts)}
      _ -> {:error, "Invalid port number: #{port_str}"}
    end
  end

  defp parse_opts(opts) do
    Enum.reduce(opts, [], fn opt, acc ->
      case opt do
        "--json" -> Keyword.put(acc, :json, true)
        "--verbose" -> Keyword.put(acc, :verbose, true)
        _ -> acc
      end
    end)
  end

  defp check_and_display(host, port, opts) do
    IO.puts("Checking SSL certificate for #{host}:#{port}...")
    IO.puts("")

    case SslCertificateChecker.check(host, port) do
      {:ok, cert_info} ->
        if Keyword.get(opts, :json) do
          display_json(cert_info)
        else
          display_formatted(cert_info, host, port)
        end

        if cert_info.is_valid do
          System.halt(0)
        else
          System.halt(2)
        end

      {:error, reason} ->
        IO.puts(:stderr, "ERROR: Failed to check certificate: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp display_formatted(cert_info, host, port) do
    IO.puts("📋 SSL Certificate Information")
    IO.puts("=" |> String.duplicate(60))
    IO.puts("Host:              #{host}:#{port}")
    IO.puts("Common Name:       #{cert_info.common_name}")
    IO.puts("Subject:           #{cert_info.subject}")
    IO.puts("Issuer:            #{cert_info.issuer}")
    IO.puts("Serial Number:     #{cert_info.serial_number}")
    IO.puts("")
    IO.puts("Valid From:        #{DateTime.to_string(cert_info.valid_from)}")
    IO.puts("Valid Until:       #{DateTime.to_string(cert_info.valid_until)}")
    IO.puts("")

    status = if cert_info.is_valid, do: "OK", else: "INVALID"
    IO.puts("Status:            #{status_icon} #{if cert_info.is_valid, do: "Valid", else: "Invalid/Expired"}")

    expiry_warning =
      cond do
        cert_info.days_until_expiry < 0 ->
          "ERROR:  EXPIRED #{abs(cert_info.days_until_expiry)} days ago!"

        cert_info.days_until_expiry <= 7 ->
          "WARN: CRITICAL — Expires in #{cert_info.days_until_expiry} days"

        cert_info.days_until_expiry <= 30 ->
          "WARN: Expires in #{cert_info.days_until_expiry} days"

        true ->
          "OK: Expires in #{cert_info.days_until_expiry} days"
      end

    IO.puts("Expiry:            #{expiry_warning}")

    unless Enum.empty?(cert_info.san_domains) do
      IO.puts("")
      IO.puts("Subject Alternative Names:")
      Enum.each(cert_info.san_domains, fn domain ->
        IO.puts("  - #{domain}")
      end)
    end

    IO.puts("")
  end

  defp display_json(cert_info) do
    json =
      cert_info
      |> Map.update!(:valid_from, &DateTime.to_iso8601/1)
      |> Map.update!(:valid_until, &DateTime.to_iso8601/1)
      |> Jason.encode!(pretty: true)

    IO.puts(json)
  end

  defp print_help do
    IO.puts("""
    SSL Certificate Checker

    Usage:
      ssl_certificate_checker <host> [port] [options]

    Arguments:
      host          The hostname to check (required)
      port          The port number (default: 443)

    Options:
      --json        Output in JSON format
      --verbose     Verbose output
      -h, --help    Show this help message

    Examples:
      ssl_certificate_checker google.com
      ssl_certificate_checker example.com 8443
      ssl_certificate_checker google.com 443 --json

    Exit Codes:
      0  - Certificate is valid
      1  - Error occurred during check
      2  - Certificate is invalid or expired
    """)
  end
end
