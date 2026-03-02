module X509
  # Holds the four PEM-encoded outputs of a certificate generation call.
  #
  # In self-signed mode all four fields are freshly generated.
  # In CA-signed mode `ca_cert` and `ca_key` echo back the values you provided;
  # `client_cert` and `client_key` are freshly generated and signed by that CA.
  #
  # All fields are non-empty strings on success — `X509.generate` raises
  # `X509::Error` rather than returning a bundle with empty fields.
  struct CertBundle
    # PEM-encoded CA certificate.
    getter ca_cert : String

    # PEM-encoded CA private key (PKCS8 format).
    getter ca_key : String

    # PEM-encoded client certificate signed by the CA.
    getter client_cert : String

    # PEM-encoded client private key (PKCS8 format).
    getter client_key : String

    def initialize(
      @ca_cert : String,
      @ca_key : String,
      @client_cert : String,
      @client_key : String,
    )
    end
  end
end
