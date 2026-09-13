defmodule SslCertificateChecker.CLITest do
  # Capturing stderr is global, so these tests can't run concurrently with others.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias SslCertificateChecker.{CLI, TestServer}

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    %{port: port, cacerts: cacerts} = TestServer.start()

    cacert = Path.join(tmp_dir, "ca.pem")
    pem_entries = for der <- cacerts, do: {:Certificate, der, :not_encrypted}
    File.write!(cacert, :public_key.pem_encode(pem_entries))

    %{port: Integer.to_string(port), cacert: cacert}
  end

  describe "--json" do
    test "prints only the certificate as JSON and exits 0 when valid", %{
      port: port,
      cacert: cacert
    } do
      assert %{code: 0, stdout: stdout, stderr: ""} =
               run_cli(["localhost", port, "--json", "--cacert", cacert])

      json = Jason.decode!(stdout)
      assert json["is_valid"] == true
      assert json["verification_errors"] == []
      assert json["san_domains"] == ["localhost"]
      assert json["host"] == "localhost"
      assert json["port"] == String.to_integer(port)
      assert {:ok, _datetime, 0} = DateTime.from_iso8601(json["valid_until"])
    end

    test "exits 2 when the certificate fails verification", %{port: port} do
      # Without --cacert the generated test CA isn't trusted.
      assert %{code: 2, stdout: stdout} = run_cli(["localhost", port, "--json"])
      assert "unknown_ca" in Jason.decode!(stdout)["verification_errors"]
    end

    test "reports errors as JSON and exits 1, including when no port is given" do
      assert %{code: 1, stdout: stdout, stderr: ""} = run_cli(["--json", "example.com; rm -rf ~"])

      assert Jason.decode!(stdout) == %{
               "host" => "example.com; rm -rf ~",
               "port" => 443,
               "error" => "invalid_host",
               "message" => "Not a valid hostname or IP address"
             }
    end

    test "flattens detailed error reasons into a code and message" do
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, port} = :inet.port(socket)

      assert %{code: 1, stdout: stdout} =
               run_cli(["127.0.0.1", Integer.to_string(port), "--json", "--timeout", "200"])

      assert %{"error" => "timeout", "message" => "Timed out" <> _} = Jason.decode!(stdout)
    end
  end

  describe "text output" do
    test "prints a readable report", %{port: port, cacert: cacert} do
      assert %{code: 0, stdout: stdout, stderr: ""} =
               run_cli(["localhost", port, "--cacert", cacert])

      assert stdout =~ "Status:            Valid"
      assert stdout =~ "Key:               EC 256-bit"
      assert stdout =~ "  - localhost"
    end

    test "lists verification problems", %{port: port} do
      assert %{code: 2, stdout: stdout} = run_cli(["localhost", port])
      assert stdout =~ "Status:            INVALID"
      assert stdout =~ "  - Certificate chain is not trusted"
    end

    test "prints check errors to stderr" do
      assert %{code: 1, stdout: stdout, stderr: stderr} = run_cli(["example.com", "70000"])
      assert stderr =~ "Error: Port must be between 1 and 65535"
      refute stdout =~ "Error"
    end
  end

  describe "arguments" do
    test "--help prints usage and exits 0" do
      assert %{code: 0, stdout: stdout, stderr: ""} = run_cli(["--help"])
      assert stdout =~ "Usage: ssl_certificate_checker"
    end

    test "invalid arguments print the problem and usage to stderr and exit 1", %{
      tmp_dir: tmp_dir
    } do
      not_pem = Path.join(tmp_dir, "not.pem")
      File.write!(not_pem, "not a certificate")

      cases = [
        {[], "Missing host"},
        {["example.com", "https"], "Invalid port: https"},
        {["example.com", "443", "extra"], "Too many arguments"},
        {["example.com", "--verbose"], "Unknown option --verbose"},
        {["example.com", "--timeout", "0"], "Invalid timeout: 0"},
        {["example.com", "--timeout", "soon"], "Invalid value for --timeout: soon"},
        {["example.com", "--cacert", Path.join(tmp_dir, "missing.pem")], "Cannot read"},
        {["example.com", "--cacert", not_pem], "No PEM certificates found"}
      ]

      for {args, message} <- cases do
        assert %{code: 1, stdout: "", stderr: stderr} = run_cli(args)
        assert stderr =~ message, "expected #{inspect(args)} to report #{inspect(message)}"
        assert stderr =~ "Usage:"
      end
    end
  end

  defp run_cli(args) do
    {{code, stdout}, stderr} = with_io(:stderr, fn -> with_io(fn -> CLI.run(args) end) end)
    %{code: code, stdout: stdout, stderr: stderr}
  end
end
