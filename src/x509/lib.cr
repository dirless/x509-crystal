@[Link("x509", ldflags: "-L#{__DIR__}/../../ -L#{__DIR__}/../../dist -Wl,-rpath,#{__DIR__}/../../ -Wl,-rpath,#{__DIR__}/../../dist -lx509")]
lib LibX509
  # Result struct returned by x509_generate.
  # All char* fields are heap-allocated by Go and must be freed by x509_free.
  struct Result
    ca_cert     : UInt8*
    ca_key      : UInt8*
    client_cert : UInt8*
    client_key  : UInt8*
    error       : UInt8*
    status      : Int32   # 0 = success, 1 = error
  end

  # Generate a CA certificate and a client certificate.
  #
  # Parameters:
  #   cn              - common name for both certificates
  #   days            - validity period in days
  #   ca_algo         - CA key algorithm: 0 = ECDSA P-256, 1 = RSA
  #   client_algo     - client key algorithm: 0 = ECDSA P-256, 1 = RSA
  #   ca_rsa_bits     - RSA bit size for CA key (ignored when ca_algo = 0)
  #   client_rsa_bits - RSA bit size for client key (ignored when client_algo = 0)
  #   provided_ca_cert - PEM of existing CA cert, or NULL for self-signed mode
  #   provided_ca_key  - PEM of matching CA private key, or NULL for self-signed mode
  #
  # Returns a heap-allocated Result. Caller MUST call x509_free when done.
  fun x509_generate(
    cn : UInt8*,
    days : Int32,
    ca_algo : Int32,
    client_algo : Int32,
    ca_rsa_bits : Int32,
    client_rsa_bits : Int32,
    provided_ca_cert : UInt8*,
    provided_ca_key : UInt8*,
  ) : Result*

  # Frees all memory allocated by x509_generate.
  # Safe to call with a null pointer.
  fun x509_free(result : Result*) : Void
end
