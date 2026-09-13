defmodule SslCertificateChecker do
  @moduledoc """
  Inspects and validates the TLS certificate a server presents.

  Certificates are fetched with Erlang's built-in `:ssl` application, so no `openssl`
  binary or shell is involved and the library runs anywhere the BEAM does. Every check
  performs full verification (trusted chain, hostname match, and validity period) and
  reports each problem it finds instead of aborting, so certificates that are
  self-signed, expired, or issued for another name can still be inspected.

  Requires Erlang/OTP 25 or later, which provides access to the operating system's
  trusted CA store.

  ## Examples

      {:ok, cert} = SslCertificateChecker.check("google.com")
      cert.is_valid             #=> true
      cert.verification_errors  #=> []
      cert.days_until_expiry    #=> 54

      {:ok, cert} = SslCertificateChecker.check("self-signed.badssl.com")
      cert.is_valid             #=> false
      cert.verification_errors  #=> [:selfsigned_peer]

  Input is validated before any connection is attempted:

      iex> SslCertificateChecker.check("example.com; rm -rf ~")
      {:error, :invalid_host}

      iex> SslCertificateChecker.check("example.com", 70_000)
      {:error, :invalid_port}
  """

  require Logger
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

  Record.defrecordp(:validity, :Validity, Record.extract(:Validity, from_lib: @public_key_hrl))

  Record.defrecordp(
    :attribute,
    :AttributeTypeAndValue,
    Record.extract(:AttributeTypeAndValue, from_lib: @public_key_hrl)
  )

  Record.defrecordp(:extension, :Extension, Record.extract(:Extension, from_lib: @public_key_hrl))

  Record.defrecordp(
    :public_key_info,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: @public_key_hrl)
  )

  Record.defrecordp(
    :public_key_algorithm,
    :PublicKeyAlgorithm,
    Record.extract(:PublicKeyAlgorithm, from_lib: @public_key_hrl)
  )

  Record.defrecordp(
    :signature_algorithm,
    :SignatureAlgorithm,
    Record.extract(:SignatureAlgorithm, from_lib: @public_key_hrl)
  )

  Record.defrecordp(
    :rsa_public_key,
    :RSAPublicKey,
    Record.extract(:RSAPublicKey, from_lib: @public_key_hrl)
  )

  @type certificate_info :: %{
          subject: String.t(),
          issuer: String.t(),
          common_name: String.t(),
          san_domains: [String.t()],
          serial_number: String.t(),
          valid_from: DateTime.t(),
          valid_until: DateTime.t(),
          days_until_expiry: integer(),
          is_valid: boolean(),
          verification_errors: [atom()],
          signature_algorithm: String.t(),
          key_type: String.t(),
          key_size: pos_integer() | nil,
          tls_version: String.t(),
          cipher_suite: String.t()
        }

  @type error_reason ::
          :invalid_host
          | :invalid_port
          | :no_trusted_certificates
          | :timeout
          | :nxdomain
          | :connection_refused
          | :invalid_certificate
          | {:connection_failed, atom()}
          | {:tls_handshake_failed, String.t()}

  @type check_result :: {:ok, certificate_info()} | {:error, error_reason()}

  @default_port 443
  @default_timeout 10_000
  @warning_days 30
  @seconds_per_day 86_400

  @oid_common_name {2, 5, 4, 3}
  @oid_organization {2, 5, 4, 10}
  @oid_subject_alt_name {2, 5, 29, 17}
  @oid_rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @oid_rsassa_pss {1, 2, 840, 113_549, 1, 1, 10}
  @oid_ec_public_key {1, 2, 840, 10_045, 2, 1}
  @oid_dsa {1, 2, 840, 10_040, 4, 1}
  @oid_ed25519 {1, 3, 101, 112}
  @oid_ed448 {1, 3, 101, 113}

  @curve_sizes %{
    {1, 2, 840, 10_045, 3, 1, 7} => 256,
    {1, 3, 132, 0, 34} => 384,
    {1, 3, 132, 0, 35} => 521
  }

  @signature_algorithms %{
    {1, 2, 840, 113_549, 1, 1, 5} => "sha1WithRSAEncryption",
    {1, 2, 840, 113_549, 1, 1, 10} => "rsassaPss",
    {1, 2, 840, 113_549, 1, 1, 11} => "sha256WithRSAEncryption",
    {1, 2, 840, 113_549, 1, 1, 12} => "sha384WithRSAEncryption",
    {1, 2, 840, 113_549, 1, 1, 13} => "sha512WithRSAEncryption",
    {1, 2, 840, 10_045, 4, 1} => "ecdsa-with-SHA1",
    {1, 2, 840, 10_045, 4, 3, 2} => "ecdsa-with-SHA256",
    {1, 2, 840, 10_045, 4, 3, 3} => "ecdsa-with-SHA384",
    {1, 2, 840, 10_045, 4, 3, 4} => "ecdsa-with-SHA512",
    {1, 3, 101, 112} => "Ed25519",
    {1, 3, 101, 113} => "Ed448"
  }

  @doc """
  Connects to `host` on `port` and returns details of the certificate it presents.

  The check succeeds whenever a certificate can be retrieved, even one that fails
  verification; use `:is_valid` and `:verification_errors` for the outcome. Common
  verification errors are `:unknown_ca`, `:selfsigned_peer`, `:hostname_check_failed`,
  and `:cert_expired`.

  `host` must be a DNS hostname or an IP address literal. Anything else, including URLs
  and strings containing whitespace or shell metacharacters, returns
  `{:error, :invalid_host}` without making a connection.

  ## Options

    * `:timeout` - connection and handshake timeout in milliseconds (default: 10000)
    * `:cacerts` - DER-encoded CA certificates to trust instead of the operating
      system's store, e.g. for servers using a private CA

  ## Examples

      SslCertificateChecker.check("google.com")
      SslCertificateChecker.check("example.com", 8443)
      SslCertificateChecker.check("internal.example", 443, timeout: 5000, cacerts: [ca_der])
  """
  @spec check(String.t(), :inet.port_number(), keyword()) :: check_result()
  def check(host, port \\ @default_port, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    with {:ok, target} <- parse_host(host),
         :ok <- validate_port(port),
         {:ok, cacerts} <- trusted_cacerts(opts),
         {:ok, der, connection_info, verification_errors} <-
           fetch_certificate(target, port, cacerts, timeout) do
      build_certificate_info(der, connection_info, verification_errors)
    end
  end

  @doc """
  Checks whether the certificate is trusted, matches the host, and is within its
  validity period.

  Accepts the same options as `check/3`.

  ## Examples

      SslCertificateChecker.is_valid?("google.com")
      #=> {:ok, true}
  """
  @spec is_valid?(String.t(), :inet.port_number(), keyword()) ::
          {:ok, boolean()} | {:error, error_reason()}
  # Public API name predates the Credo check; renaming it would break callers.
  # credo:disable-for-next-line Credo.Check.Readability.PredicateFunctionNames
  def is_valid?(host, port \\ @default_port, opts \\ []) do
    with {:ok, cert} <- check(host, port, opts), do: {:ok, cert.is_valid}
  end

  @doc """
  Gets the number of whole days until the certificate expires.

  Returns a negative number if it has already expired. Accepts the same options as
  `check/3`.

  ## Examples

      SslCertificateChecker.days_until_expiry("google.com")
      #=> {:ok, 45}
  """
  @spec days_until_expiry(String.t(), :inet.port_number(), keyword()) ::
          {:ok, integer()} | {:error, error_reason()}
  def days_until_expiry(host, port \\ @default_port, opts \\ []) do
    with {:ok, cert} <- check(host, port, opts), do: {:ok, cert.days_until_expiry}
  end

  @doc """
  Checks whether the certificate expires within the warning threshold.

  Accepts the same options as `check/3`, plus `:warning_days` (default: 30).

  ## Examples

      SslCertificateChecker.expiring_soon?("google.com")
      #=> {:ok, false}

      SslCertificateChecker.expiring_soon?("google.com", 443, warning_days: 60)
      #=> {:ok, true}
  """
  @spec expiring_soon?(String.t(), :inet.port_number(), keyword()) ::
          {:ok, boolean()} | {:error, error_reason()}
  def expiring_soon?(host, port \\ @default_port, opts \\ []) do
    warning_days = Keyword.get(opts, :warning_days, @warning_days)

    with {:ok, days} <- days_until_expiry(host, port, opts), do: {:ok, days <= warning_days}
  end

  # Input validation

  defp parse_host(host) when is_binary(host) do
    with true <- String.valid?(host),
         {:ok, ip} <- :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, {:ip, ip}}
    else
      _not_an_ip -> parse_hostname(host)
    end
  end

  defp parse_host(_host), do: {:error, :invalid_host}

  defp parse_hostname(host) do
    name = String.replace_suffix(host, ".", "")

    if byte_size(name) in 1..253 and name |> String.split(".") |> Enum.all?(&valid_label?/1) do
      {:ok, {:hostname, name}}
    else
      {:error, :invalid_host}
    end
  end

  defp valid_label?(label) do
    Regex.match?(~r/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i, label)
  end

  defp validate_port(port) when is_integer(port) and port in 1..65_535, do: :ok
  defp validate_port(_port), do: {:error, :invalid_port}

  defp trusted_cacerts(opts) do
    cacerts =
      case Keyword.fetch(opts, :cacerts) do
        {:ok, cacerts} -> cacerts
        :error -> system_cacerts()
      end

    if cacerts == [], do: {:error, :no_trusted_certificates}, else: {:ok, cacerts}
  end

  defp system_cacerts do
    :public_key.cacerts_get()
  rescue
    error ->
      Logger.warning("Could not load the system CA store: #{Exception.message(error)}")
      []
  end

  # Fetching

  # The handshake runs in its own process so that verification results sent from
  # `verify_fun` can never leak into the caller's mailbox, even after a timeout.
  defp fetch_certificate(target, port, cacerts, timeout) do
    task = Task.async(fn -> connect_and_inspect(target, port, cacerts, timeout) end)

    case Task.yield(task, timeout + 1_000) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      nil -> {:error, :timeout}
    end
  end

  defp connect_and_inspect(target, port, cacerts, timeout) do
    ref = make_ref()

    ssl_options = [
      active: false,
      verify: :verify_peer,
      cacerts: cacerts,
      # Record every verification failure but let the handshake finish so broken
      # certificates can still be inspected. No application data is ever sent.
      verify_fun: {&record_verification_result/3, {self(), ref}},
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]

    case :ssl.connect(connect_address(target), port, ssl_options, timeout) do
      {:ok, socket} ->
        result = inspect_connection(socket, collect_verification_errors(ref))
        :ssl.close(socket)
        result

      {:error, reason} ->
        {:error, connect_error(reason)}
    end
  end

  # A charlist hostname is sent as SNI and verified as a DNS name; an IP tuple
  # disables SNI and is verified against the certificate's IP address entries.
  defp connect_address({:hostname, name}), do: String.to_charlist(name)
  defp connect_address({:ip, ip}), do: ip

  defp record_verification_result(_cert, {:extension, _extension}, state), do: {:unknown, state}

  defp record_verification_result(_cert, {:bad_cert, reason}, {pid, ref} = state) do
    send(pid, {ref, verification_error(reason)})
    {:valid, state}
  end

  defp record_verification_result(_cert, _valid_or_valid_peer, state), do: {:valid, state}

  defp verification_error(reason) when is_atom(reason), do: reason
  defp verification_error({reason, _details}) when is_atom(reason), do: reason
  defp verification_error(_reason), do: :unknown_verification_error

  defp collect_verification_errors(ref, errors \\ []) do
    receive do
      {^ref, error} -> collect_verification_errors(ref, [error | errors])
    after
      0 -> errors |> Enum.reverse() |> Enum.uniq()
    end
  end

  defp inspect_connection(socket, verification_errors) do
    with {:ok, der} <- :ssl.peercert(socket),
         {:ok, info} <-
           :ssl.connection_information(socket, [:protocol, :selected_cipher_suite]) do
      {:ok, der, info, verification_errors}
    else
      {:error, reason} -> {:error, {:tls_handshake_failed, inspect(reason)}}
    end
  end

  defp connect_error(:timeout), do: :timeout
  defp connect_error(:nxdomain), do: :nxdomain
  defp connect_error(:econnrefused), do: :connection_refused

  defp connect_error({:tls_alert, {_alert, description}}),
    do: {:tls_handshake_failed, to_string(description)}

  defp connect_error(reason) when is_atom(reason), do: {:connection_failed, reason}
  defp connect_error(reason), do: {:tls_handshake_failed, inspect(reason)}

  # Certificate decoding

  defp build_certificate_info(der, connection_info, verification_errors) do
    otp_certificate(
      tbsCertificate: tbs,
      signatureAlgorithm: signature_algorithm(algorithm: signature_oid)
    ) = :public_key.pkix_decode_cert(der, :otp)

    tbs_certificate(
      serialNumber: serial,
      issuer: issuer,
      subject: subject,
      validity: validity(notBefore: not_before, notAfter: not_after),
      subjectPublicKeyInfo: key_info,
      extensions: extensions
    ) = tbs

    {:ok, valid_from} = parse_asn1_time(not_before)
    {:ok, valid_until} = parse_asn1_time(not_after)
    {key_type, key_size} = public_key_details(key_info)
    subject_attributes = name_attributes(subject)
    now = DateTime.utc_now()

    in_validity_period =
      DateTime.compare(now, valid_from) != :lt and DateTime.compare(now, valid_until) == :lt

    {:ok,
     %{
       subject: display_name(subject_attributes),
       issuer: issuer |> name_attributes() |> display_name(),
       common_name: Map.get(subject_attributes, @oid_common_name, ""),
       san_domains: san_domains(extensions),
       serial_number: Integer.to_string(serial, 16),
       valid_from: valid_from,
       valid_until: valid_until,
       days_until_expiry: Integer.floor_div(DateTime.diff(valid_until, now), @seconds_per_day),
       is_valid: verification_errors == [] and in_validity_period,
       verification_errors: verification_errors,
       signature_algorithm:
         Map.get(@signature_algorithms, signature_oid, oid_string(signature_oid)),
       key_type: key_type,
       key_size: key_size,
       tls_version: connection_info |> Keyword.fetch!(:protocol) |> tls_version_name(),
       cipher_suite:
         connection_info
         |> Keyword.fetch!(:selected_cipher_suite)
         |> :ssl.suite_to_str()
         |> to_string()
     }}
  rescue
    error ->
      Logger.debug("Could not decode certificate: #{Exception.message(error)}")
      {:error, :invalid_certificate}
  end

  defp name_attributes({:rdnSequence, rdns}) do
    for rdn <- rdns, attribute(type: type, value: value) <- rdn, reduce: %{} do
      attributes -> Map.put_new(attributes, type, attribute_string(value))
    end
  end

  defp attribute_string({_string_type, value}), do: attribute_string(value)
  defp attribute_string(value) when is_list(value), do: List.to_string(value)

  defp attribute_string(value) when is_binary(value) do
    if String.valid?(value), do: value, else: Base.encode16(value)
  end

  defp attribute_string(value), do: inspect(value)

  defp display_name(attributes) do
    Map.get(attributes, @oid_organization) || Map.get(attributes, @oid_common_name, "")
  end

  defp san_domains(extensions) when is_list(extensions) do
    Enum.flat_map(extensions, fn
      extension(extnID: @oid_subject_alt_name, extnValue: names) when is_list(names) ->
        for {:dNSName, name} <- names, do: to_string(name)

      _other_extension ->
        []
    end)
  end

  defp san_domains(_no_extensions), do: []

  defp public_key_details(
         public_key_info(
           algorithm: public_key_algorithm(algorithm: oid, parameters: parameters),
           subjectPublicKey: key
         )
       ) do
    case oid do
      @oid_rsa_encryption -> {"RSA", rsa_key_size(key)}
      @oid_rsassa_pss -> {"RSA-PSS", rsa_key_size(key)}
      @oid_ec_public_key -> {"EC", curve_size(parameters)}
      @oid_ed25519 -> {"Ed25519", nil}
      @oid_ed448 -> {"Ed448", nil}
      @oid_dsa -> {"DSA", nil}
      other -> {oid_string(other), nil}
    end
  end

  defp rsa_key_size(rsa_public_key(modulus: modulus)), do: modulus |> Integer.digits(2) |> length()
  defp rsa_key_size(_key), do: nil

  defp curve_size({:namedCurve, oid}), do: Map.get(@curve_sizes, oid)
  defp curve_size(_parameters), do: nil

  defp oid_string(oid), do: oid |> Tuple.to_list() |> Enum.join(".")

  # RFC 5280: UTCTime years 50-99 are 19xx, 00-49 are 20xx.
  defp parse_asn1_time({:utcTime, time}) do
    <<year::binary-size(2), rest::binary>> = to_string(time)
    century = if String.to_integer(year) >= 50, do: "19", else: "20"
    parse_asn1_time({:generalTime, century <> year <> rest})
  end

  defp parse_asn1_time({:generalTime, time}) do
    <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
      minute::binary-size(2), second::binary-size(2), "Z">> = to_string(time)

    [year, month, day, hour, minute, second] =
      Enum.map([year, month, day, hour, minute, second], &String.to_integer/1)

    with {:ok, date} <- Date.new(year, month, day),
         {:ok, time} <- Time.new(hour, minute, second) do
      DateTime.new(date, time)
    end
  end

  defp tls_version_name(:"tlsv1.3"), do: "TLSv1.3"
  defp tls_version_name(:"tlsv1.2"), do: "TLSv1.2"
  defp tls_version_name(:"tlsv1.1"), do: "TLSv1.1"
  defp tls_version_name(:tlsv1), do: "TLSv1.0"
  defp tls_version_name(other), do: to_string(other)
end
