#!/usr/bin/env elixir

# Example script demonstrating various uses of SslCertificateChecker
# Run with: elixir examples/usage_examples.exs

Mix.install([
  {:ssl_certificate_checker, path: "."}
])

defmodule Examples do
  @moduledoc """
  Example usage of SslCertificateChecker
  """

  def run do
    IO.puts("\n" <> String.duplicate("=", 70))
    IO.puts("SSL Certificate Checker - Examples")
    IO.puts(String.duplicate("=", 70) <> "\n")

    example_basic_check()
    example_multiple_hosts()
    example_expiry_monitoring()
    example_custom_port()
  end

  defp example_basic_check do
    IO.puts("INFO: Example 1 - Basic Certificate Check")
    IO.puts(String.duplicate("-", 70))

    case SslCertificateChecker.check("google.com") do
      {:ok, cert} ->
        IO.puts("OK: Certificate retrieved successfully")
        IO.puts("   Subject: #{cert.subject}")
        IO.puts("   Issuer: #{cert.issuer}")
        IO.puts("   Valid until: #{DateTime.to_string(cert.valid_until)}")
        IO.puts("   Days until expiry: #{cert.days_until_expiry}")
        IO.puts("   Common Name: #{cert.common_name}")
        IO.puts("   SAN Domains: #{inspect(cert.san_domains)}")

      {:error, reason} ->
        IO.puts("ERROR: #{inspect(reason)}")
    end

    IO.puts("")
  end

  defp example_multiple_hosts do
    IO.puts("INFO: Example 2 - Check Multiple Hosts Concurrently")
    IO.puts(String.duplicate("-", 70))

    hosts = ["google.com", "github.com", "cloudflare.com"]

    results =
      hosts
      |> Task.async_stream(
        fn host ->
          case SslCertificateChecker.check(host) do
            {:ok, cert} ->
              {host, :ok, cert.days_until_expiry, cert.is_valid}

            {:error, reason} ->
              {host, :error, reason}
          end
        end,
        timeout: 10_000,
        max_concurrency: 5
      )
      |> Enum.map(fn {:ok, result} -> result end)

    Enum.each(results, fn
      {host, :ok, days, true} ->
        IO.puts("OK      #{String.pad_trailing(host, 20)} - #{days} days remaining")

      {host, :ok, days, false} ->
        IO.puts("INVALID #{String.pad_trailing(host, 20)} - #{days} days remaining")

      {host, :error, reason} ->
        IO.puts("ERROR   #{String.pad_trailing(host, 20)} - #{reason}")
    end)

    IO.puts("")
  end

  defp example_expiry_monitoring do
    IO.puts("INFO: Example 3 - Certificate Expiry Monitoring")
    IO.puts(String.duplicate("-", 70))

    hosts = ["google.com", "github.com", "stackoverflow.com"]

    critical = []
    warning = []
    ok = []

    Enum.each(hosts, fn host ->
      case SslCertificateChecker.check(host) do
        {:ok, cert} ->
          cond do
            cert.days_until_expiry < 0 ->
              IO.puts("EXPIRED:  #{host} (expired #{abs(cert.days_until_expiry)} days ago)")

            cert.days_until_expiry <= 7 ->
              IO.puts("CRITICAL: #{host} (expires in #{cert.days_until_expiry} days)")
              critical = [host | critical]

            cert.days_until_expiry <= 30 ->
              IO.puts("WARNING:  #{host} (expires in #{cert.days_until_expiry} days)")
              warning = [host | warning]

            true ->
              IO.puts("OK:       #{host} (expires in #{cert.days_until_expiry} days)")
              ok = [host | ok]
          end

        {:error, reason} ->
          IO.puts("ERROR: #{host} - #{reason}")
      end
    end)

    IO.puts("\nSummary:")
    IO.puts("  OK: #{length(ok)}")
    IO.puts("  Warnings: #{length(warning)}")
    IO.puts("  Critical: #{length(critical)}")
    IO.puts("")
  end

  defp example_custom_port do
    IO.puts("INFO: Example 4 - Check Certificate on Custom Port")
    IO.puts(String.duplicate("-", 70))

    case SslCertificateChecker.check("google.com", 443) do
      {:ok, cert} ->
        IO.puts("OK: Certificate on port 443")
        IO.puts("   Valid: #{cert.is_valid}")
        IO.puts("   Days remaining: #{cert.days_until_expiry}")

      {:error, reason} ->
        IO.puts("ERROR: #{inspect(reason)}")
    end

    IO.puts("")
  end
end

# Run the examples
Examples.run()

IO.puts(String.duplicate("=", 70))
IO.puts("Examples completed")
IO.puts(String.duplicate("=", 70))
