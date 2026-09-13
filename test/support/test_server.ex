defmodule SslCertificateChecker.TestServer do
  @moduledoc false
  # Local TLS servers presenting generated certificate chains, so tests never need the network.

  require Record

  @public_key_hrl "public_key/include/public_key.hrl"

  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: @public_key_hrl)
  )

  Record.defrecordp(
    :tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: @public_key_hrl)
  )

  Record.defrecordp(:extension, :Extension, Record.extract(:Extension, from_lib: @public_key_hrl))

  @subject_alt_name {2, 5, 29, 17}
  @authority_key_identifier {2, 5, 29, 35}

  # OTP's defaults (secp256k1 keys, SHA-1 signatures) can't be negotiated in TLS 1.2/1.3.
  # The curve is given by OID (P-256), as public_key's type specs require.
  @secp256r1 {1, 2, 840, 10_045, 3, 1, 7}
  @cert_opts [key: {:namedCurve, @secp256r1}, digest: :sha256]

  @doc """
  Starts a TLS server on 127.0.0.1 presenting a root -> intermediate -> leaf chain.

  Options:

    * `:san` - subjectAltName entries for the leaf (default: `[dNSName: ~c"localhost"]`)
    * `:validity` - leaf validity as `{from, to}` date tuples, e.g. `{{2020, 1, 1}, {2020, 6, 1}}`
    * `:cross_signed_root` - when `true`, the server sends a copy of the root cross-signed by
      another, untrusted root instead of omitting it, like many public sites do during root
      migrations. Clients that trust the self-signed root must find that alternative path.

  Returns `%{port: port, cacerts: [root_der]}`. The server stops when the calling test exits.
  """
  def start(opts \\ []) do
    san = Keyword.get(opts, :san, dNSName: ~c"localhost")

    leaf =
      @cert_opts ++
        [extensions: [extension(extnID: @subject_alt_name, critical: false, extnValue: san)]] ++
        Keyword.take(opts, [:validity])

    %{server_config: server_config, client_config: client_config} =
      :public_key.pkix_test_data(%{
        server_chain: %{root: @cert_opts, intermediates: [@cert_opts], peer: leaf},
        client_chain: %{root: @cert_opts, intermediates: [], peer: @cert_opts}
      })

    client_cacerts = Keyword.fetch!(client_config, :cacerts)
    root_der = Enum.find(client_cacerts, &self_signed?/1)

    server_config =
      if Keyword.get(opts, :cross_signed_root, false) do
        replace_root_with_cross_signed(server_config, root_der)
      else
        server_config
      end

    {:ok, listen_socket} =
      :ssl.listen(0, [ip: {127, 0, 0, 1}, active: false, reuseaddr: true] ++ server_config)

    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    acceptor = spawn(fn -> accept_loop(listen_socket) end)
    ExUnit.Callbacks.on_exit(fn -> Process.exit(acceptor, :kill) end)

    %{port: port, cacerts: client_cacerts}
  end

  defp self_signed?(der),
    do: der |> :public_key.pkix_decode_cert(:otp) |> :public_key.pkix_is_self_signed()

  defp replace_root_with_cross_signed(server_config, root_der) do
    untrusted_root = :public_key.pkix_test_root_cert(~c"Untrusted Root CA", @cert_opts)
    cross_signed = cross_sign(root_der, untrusted_root)
    cacerts = Keyword.fetch!(server_config, :cacerts)

    if root_der not in cacerts, do: raise("expected the root in the server's cacerts")

    Keyword.put(server_config, :cacerts, [cross_signed | List.delete(cacerts, root_der)])
  end

  # Same subject and public key as `root_der`, but issued and signed by `signer`.
  defp cross_sign(root_der, signer) do
    otp_certificate(tbsCertificate: root_tbs) = :public_key.pkix_decode_cert(root_der, :otp)
    otp_certificate(tbsCertificate: signer_tbs) = :public_key.pkix_decode_cert(signer.cert, :otp)

    extensions =
      case tbs_certificate(root_tbs, :extensions) do
        extensions when is_list(extensions) ->
          Enum.reject(extensions, &(extension(&1, :extnID) == @authority_key_identifier))

        none ->
          none
      end

    root_tbs
    |> tbs_certificate(
      issuer: tbs_certificate(signer_tbs, :subject),
      serialNumber: :rand.uniform(1_000_000_000),
      extensions: extensions
    )
    |> :public_key.pkix_sign(signer.key)
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
