defmodule SslCertificateCheckerTest do
  use ExUnit.Case, async: true
  doctest SslCertificateChecker

  import SslCertificateChecker,
    only: [check: 1, check: 2, check: 3, is_valid?: 3, days_until_expiry: 3, expiring_soon?: 3]

  alias SslCertificateChecker.TestServer

  describe "check/3 with a trusted certificate" do
    setup do
      TestServer.start()
    end

    test "returns certificate details and passes verification", %{port: port, cacerts: cacerts} do
      assert {:ok, cert} = check("localhost", port, cacerts: cacerts)

      assert cert.is_valid
      assert cert.verification_errors == []
      assert cert.san_domains == ["localhost"]
      assert cert.days_until_expiry in 5..8
      assert DateTime.compare(cert.valid_from, DateTime.utc_now()) == :lt
      assert DateTime.compare(cert.valid_until, DateTime.utc_now()) == :gt
      assert cert.serial_number =~ ~r/\A-?[0-9A-F]+\z/
      assert cert.issuer != ""
      assert cert.tls_version in ["TLSv1.2", "TLSv1.3"]
      assert cert.cipher_suite =~ "TLS_"
      assert cert.key_type == "EC"
      assert cert.key_size == 256
      assert cert.signature_algorithm == "ecdsa-with-SHA256"
    end

    test "accepts a fully qualified hostname with a trailing dot", %{port: port, cacerts: cacerts} do
      assert {:ok, %{is_valid: true}} = check("localhost.", port, cacerts: cacerts)
    end

    test "verifies an IP address against the certificate's IP entries", %{
      port: port,
      cacerts: cacerts
    } do
      assert {:ok, cert} = check("127.0.0.1", port, cacerts: cacerts)
      assert cert.verification_errors == [:hostname_check_failed]
      refute cert.is_valid
    end

    test "convenience functions pass options through", %{port: port, cacerts: cacerts} do
      opts = [cacerts: cacerts]

      assert {:ok, true} = is_valid?("localhost", port, opts)
      assert {:ok, days} = days_until_expiry("localhost", port, opts)
      assert days > 0
      assert {:ok, true} = expiring_soon?("localhost", port, opts)
      assert {:ok, false} = expiring_soon?("localhost", port, [warning_days: 1] ++ opts)
    end
  end

  describe "check/3 with a certificate that fails verification" do
    test "reports an untrusted chain" do
      %{port: port} = TestServer.start()
      %{cacerts: unrelated_cacerts} = TestServer.start()

      assert {:ok, cert} = check("localhost", port, cacerts: unrelated_cacerts)
      refute cert.is_valid
      assert :unknown_ca in cert.verification_errors
    end

    test "reports a hostname mismatch" do
      %{port: port, cacerts: cacerts} = TestServer.start(san: [dNSName: ~c"other.example"])

      assert {:ok, cert} = check("localhost", port, cacerts: cacerts)
      refute cert.is_valid
      assert cert.verification_errors == [:hostname_check_failed]
      assert cert.san_domains == ["other.example"]
    end

    test "accepts an IP address listed in the certificate" do
      %{port: port, cacerts: cacerts} = TestServer.start(san: [iPAddress: <<127, 0, 0, 1>>])

      assert {:ok, %{is_valid: true, verification_errors: []}} =
               check("127.0.0.1", port, cacerts: cacerts)
    end

    test "reports an expired certificate" do
      %{port: port, cacerts: cacerts} = TestServer.start(validity: {{2020, 1, 1}, {2020, 6, 1}})

      assert {:ok, cert} = check("localhost", port, cacerts: cacerts)
      refute cert.is_valid
      assert :cert_expired in cert.verification_errors
      assert DateTime.to_date(cert.valid_until) == ~D[2020-06-01]
      assert cert.days_until_expiry < 0
    end
  end

  describe "check/3 connection failures" do
    test "returns :connection_refused when nothing is listening" do
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(socket)
      :ok = :gen_tcp.close(socket)

      assert check("127.0.0.1", port) == {:error, :connection_refused}
    end

    test "returns :timeout when the server never completes a handshake" do
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, port} = :inet.port(socket)

      assert check("127.0.0.1", port, timeout: 200) == {:error, :timeout}
    end

    test "returns :no_trusted_certificates when the trust store is empty" do
      assert check("localhost", 443, cacerts: []) == {:error, :no_trusted_certificates}
    end
  end

  describe "input validation" do
    test "rejects anything that is not a hostname or IP address" do
      invalid_hosts = [
        "",
        ".",
        "google.com; rm -rf ~",
        "$(reboot)",
        "`id`",
        "google.com | cat",
        "google.com\nevil.com",
        "google.com:443",
        "https://google.com",
        "a b.com",
        "-leading.com",
        "trailing-.com",
        "bad..dots",
        String.duplicate("a", 64) <> ".com",
        String.duplicate("abcdefghi.", 26),
        <<0xFF, 0xFE>>,
        nil,
        :google,
        ~c"google.com"
      ]

      for host <- invalid_hosts do
        assert check(host) == {:error, :invalid_host}, "expected #{inspect(host)} to be rejected"
      end
    end

    test "rejects ports outside 1..65535" do
      for port <- [0, -1, 65_536, "443", nil] do
        assert check("localhost", port) == {:error, :invalid_port}
      end
    end
  end

  describe "public hosts" do
    @describetag :external

    test "google.com has a valid certificate" do
      assert {:ok, cert} = check("google.com")
      assert cert.is_valid
      assert cert.verification_errors == []
    end

    test "self-signed.badssl.com is reported as self-signed" do
      assert {:ok, cert} = check("self-signed.badssl.com")
      refute cert.is_valid
      assert :selfsigned_peer in cert.verification_errors
    end

    test "wrong.host.badssl.com is reported as a hostname mismatch" do
      assert {:ok, cert} = check("wrong.host.badssl.com")
      assert :hostname_check_failed in cert.verification_errors
    end

    test "expired.badssl.com is reported as expired" do
      assert {:ok, cert} = check("expired.badssl.com")
      assert :cert_expired in cert.verification_errors
    end

    test "unresolvable domains return :nxdomain" do
      assert check("does-not-exist.invalid") == {:error, :nxdomain}
    end
  end
end
