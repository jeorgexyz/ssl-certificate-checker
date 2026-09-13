defmodule SslCertificateChecker.TestServer do
  @moduledoc false
  # Local TLS servers presenting generated certificate chains, so tests never need the network.

  require Record

  Record.defrecordp(
    :extension,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/public_key.hrl")
  )

  @subject_alt_name {2, 5, 29, 17}

  @doc """
  Starts a TLS server on 127.0.0.1 presenting a root -> intermediate -> leaf chain.

  Options:

    * `:san` - subjectAltName entries for the leaf (default: `[dNSName: ~c"localhost"]`)
    * `:validity` - leaf validity as `{from, to}` date tuples, e.g. `{{2020, 1, 1}, {2020, 6, 1}}`

  Returns `%{port: port, cacerts: [root_der]}`. The server stops when the calling test exits.
  """
  def start(opts \\ []) do
    san = Keyword.get(opts, :san, dNSName: ~c"localhost")

    # OTP's defaults (secp256k1 keys, SHA-1 signatures) can't be negotiated in TLS 1.2/1.3.
    cert_opts = [key: {:namedCurve, :secp256r1}, digest: :sha256]

    leaf =
      cert_opts ++
        [extensions: [extension(extnID: @subject_alt_name, critical: false, extnValue: san)]] ++
        Keyword.take(opts, [:validity])

    %{server_config: server_config, client_config: client_config} =
      :public_key.pkix_test_data(%{
        server_chain: %{root: cert_opts, intermediates: [cert_opts], peer: leaf},
        client_chain: %{root: cert_opts, intermediates: [], peer: cert_opts}
      })

    {:ok, listen_socket} =
      :ssl.listen(0, [ip: {127, 0, 0, 1}, active: false, reuseaddr: true] ++ server_config)

    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    acceptor = spawn(fn -> accept_loop(listen_socket) end)
    ExUnit.Callbacks.on_exit(fn -> Process.exit(acceptor, :kill) end)

    %{port: port, cacerts: Keyword.fetch!(client_config, :cacerts)}
  end

  defp accept_loop(listen_socket) do
    case :ssl.transport_accept(listen_socket) do
      {:ok, socket} ->
        with {:ok, tls_socket} <- :ssl.handshake(socket, 5_000) do
          :ssl.recv(tls_socket, 0, 1_000)
          :ssl.close(tls_socket)
        end

        accept_loop(listen_socket)

      {:error, _closed} ->
        :ok
    end
  end
end
