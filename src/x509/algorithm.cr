module X509
  # Key algorithm for certificate generation.
  # Constant values must stay in sync with AlgoECDSA / AlgoRSA in certgen_core.go.
  enum Algorithm : Int32
    # ECDSA with P-256 curve. Recommended default — smaller keys, faster
    # operations, and equally secure to RSA-3072 for mTLS use cases.
    ECDSA = 0

    # RSA. Specify key size via ca_rsa_bits / client_rsa_bits (default: 4096).
    # Use when compatibility with older systems or PKI policies requires RSA.
    RSA = 1
  end
end
