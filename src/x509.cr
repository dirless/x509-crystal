require "./x509/lib"
require "./x509/algorithm"
require "./x509/cert_bundle"

module X509
  class Error < Exception; end

  # Default RSA key size when algorithm is `Algorithm::RSA` and no explicit
  # bit size is provided. 4096 is the conservative, widely accepted default
  # for new deployments.
  DEFAULT_RSA_BITS = 4096

  # Generates a CA certificate and a client certificate signed by that CA.
  #
  # ## Self-signed mode (default)
  #
  # Omit `ca_cert` and `ca_key`. A fresh CA keypair is generated using
  # `ca_algorithm`, and the client cert is signed by it.
  #
  # ```
  # bundle = X509.generate(common_name: "tenant-abc123", days: 3650)
  # ```
  #
  # ## CA-signed mode
  #
  # Provide both `ca_cert` and `ca_key` to use an existing CA.
  # The returned bundle's `ca_cert` and `ca_key` fields will echo back
  # the values you supplied; only the client cert/key are freshly generated.
  #
  # ```
  # bundle = X509.generate(
  #   common_name: "tenant-abc123",
  #   days:        3650,
  #   ca_cert:     File.read("my-ca.crt"),
  #   ca_key:      File.read("my-ca.key"),
  # )
  # ```
  #
  # ## Mixed algorithms
  #
  # By default `client_algorithm` matches `ca_algorithm`. Override it to mix:
  #
  # ```
  # bundle = X509.generate(
  #   common_name:      "tenant-abc123",
  #   days:             3650,
  #   ca_algorithm:     X509::Algorithm::ECDSA,
  #   client_algorithm: X509::Algorithm::RSA,
  #   client_rsa_bits:  2048,
  # )
  # ```
  #
  # ## Parameters
  #
  # - `common_name` — applied to both the CA and client certificate Subject CN.
  # - `days` — validity period in days. Applies to both certs in self-signed mode;
  #   in CA-signed mode only affects the client cert (the CA's validity is fixed).
  # - `ca_algorithm` — key algorithm for the CA. Defaults to `Algorithm::ECDSA`.
  # - `client_algorithm` — key algorithm for the client cert. Defaults to
  #   `ca_algorithm`, so both use the same algorithm unless you override this.
  # - `ca_rsa_bits` — RSA key size for the CA key. Only used when
  #   `ca_algorithm` is `Algorithm::RSA`. Defaults to `DEFAULT_RSA_BITS` (4096).
  # - `client_rsa_bits` — RSA key size for the client key. Only used when
  #   `client_algorithm` is `Algorithm::RSA`. Defaults to `DEFAULT_RSA_BITS`.
  # - `ca_cert` — PEM of an existing CA certificate. Provide together with
  #   `ca_key` to use CA-signed mode. Must be `nil` for self-signed mode.
  # - `ca_key` — PEM of the private key matching `ca_cert`.
  #
  # ## Returns
  #
  # An `X509::CertBundle` with all four PEM fields populated.
  #
  # ## Raises
  #
  # `X509::Error` on any failure (invalid input, mismatched cert/key, etc.).
  def self.generate(
    common_name : String,
    days : Int32,
    ca_algorithm : Algorithm = Algorithm::ECDSA,
    client_algorithm : Algorithm? = nil,
    ca_rsa_bits : Int32 = DEFAULT_RSA_BITS,
    client_rsa_bits : Int32 = DEFAULT_RSA_BITS,
    ca_cert : String? = nil,
    ca_key : String? = nil,
  ) : CertBundle
    # client_algorithm defaults to ca_algorithm when not explicitly set.
    resolved_client_algo = client_algorithm || ca_algorithm

    # Both ca_cert and ca_key must be provided together — or neither.
    if ca_cert.nil? != ca_key.nil?
      raise Error.new("ca_cert and ca_key must both be provided, or both omitted")
    end

    ca_cert_ptr = ca_cert.try(&.to_unsafe)
    ca_key_ptr = ca_key.try(&.to_unsafe)

    result = LibX509.x509_generate(
      common_name.to_unsafe,
      days,
      ca_algorithm.value,
      resolved_client_algo.value,
      ca_rsa_bits,
      client_rsa_bits,
      ca_cert_ptr,
      ca_key_ptr,
    )

    begin
      if result.value.status != 0
        msg = result.value.error ? String.new(result.value.error.not_nil!) : "unknown error"
        raise Error.new(msg)
      end

      CertBundle.new(
        ca_cert:     String.new(result.value.ca_cert.not_nil!),
        ca_key:      String.new(result.value.ca_key.not_nil!),
        client_cert: String.new(result.value.client_cert.not_nil!),
        client_key:  String.new(result.value.client_key.not_nil!),
      )
    ensure
      LibX509.x509_free(result)
    end
  end
end
