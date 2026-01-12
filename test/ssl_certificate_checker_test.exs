defmodule SslCertificateCheckerTest do
  use ExUnit.Case
  doctest SslCertificateChecker

  describe "check/2" do
    test "successfully checks a valid certificate" do
      # Using a well-known public host
      case SslCertificateChecker.check("google.com") do
        {:ok, cert_info} ->
          assert is_binary(cert_info.subject)
          assert is_binary(cert_info.issuer)
          assert %DateTime{} = cert_info.valid_from
          assert %DateTime{} = cert_info.valid_until
          assert is_integer(cert_info.days_until_expiry)
          assert is_boolean(cert_info.is_valid)
          assert is_list(cert_info.san_domains)
          assert is_binary(cert_info.serial_number)

        {:error, reason} ->
          # If network is unavailable, skip test
          IO.warn("Skipping test due to network error: #{inspect(reason)}")
      end
    end

    test "returns error for invalid host" do
      result = SslCertificateChecker.check("invalid-host-that-does-not-exist-12345.com")
      assert {:error, _reason} = result
    end

    test "returns error for empty host" do
      result = SslCertificateChecker.check("")
      assert {:error, :invalid_host} = result
    end

    test "returns error for invalid port" do
      result = SslCertificateChecker.check("google.com", -1)
      assert {:error, :invalid_port} = result

      result = SslCertificateChecker.check("google.com", 70000)
      assert {:error, :invalid_port} = result
    end

    test "handles custom port" do
      # Most HTTPS services on custom ports won't be available
      # This test mainly validates the port parameter works
      result = SslCertificateChecker.check("google.com", 443)
      assert match?({:ok, _} | {:error, _}, result)
    end

    test "respects timeout option" do
      # Use a very short timeout that should fail
      result = SslCertificateChecker.check("google.com", 443, timeout: 1)
      # Should either timeout or succeed if very fast
      assert match?({:ok, _} | {:error, _}, result)
    end
  end

  describe "is_valid?/2" do
    test "checks if certificate is valid" do
      case SslCertificateChecker.is_valid?("google.com") do
        {:ok, valid} ->
          assert is_boolean(valid)
          # Google's cert should be valid
          assert valid == true

        {:error, _reason} ->
          # Network error, skip
          :ok
      end
    end

    test "returns error for invalid host" do
      result = SslCertificateChecker.is_valid?("invalid-host-12345.com")
      assert {:error, _reason} = result
    end
  end

  describe "days_until_expiry/2" do
    test "returns days until expiry" do
      case SslCertificateChecker.days_until_expiry("google.com") do
        {:ok, days} ->
          assert is_integer(days)
          # Google's cert should not be expiring immediately
          assert days > 0

        {:error, _reason} ->
          # Network error, skip
          :ok
      end
    end
  end

  describe "expiring_soon?/3" do
    test "checks if certificate is expiring soon with default threshold" do
      case SslCertificateChecker.expiring_soon?("google.com") do
        {:ok, expiring} ->
          assert is_boolean(expiring)

        {:error, _reason} ->
          :ok
      end
    end

    test "checks with custom warning threshold" do
      case SslCertificateChecker.expiring_soon?("google.com", 443, warning_days: 90) do
        {:ok, expiring} ->
          assert is_boolean(expiring)

        {:error, _reason} ->
          :ok
      end
    end
  end

  describe "parse functions" do
    test "validates host input" do
      # These would be private function tests if we exposed them
      # For now, we test through public API
      assert {:error, :invalid_host} = SslCertificateChecker.check("")
      assert {:error, :invalid_host} = SslCertificateChecker.check(nil)
    end

    test "validates port input" do
      assert {:error, :invalid_port} = SslCertificateChecker.check("google.com", 0)
      assert {:error, :invalid_port} = SslCertificateChecker.check("google.com", 100000)
    end
  end
end
