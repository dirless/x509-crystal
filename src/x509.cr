require "./x509/lib_x509"
require "./x509/algorithm"
require "./x509/cert_bundle"
require "openssl/x509/certificate"
require "openssl/x509/extension"
require "openssl/x509/name"

module X509
  class Error < Exception; end

  DEFAULT_RSA_BITS = 4096

  private EVP_PKEY_RSA             =   6
  private EVP_PKEY_EC              = 408
  private NID_X9_62_prime256v1     = 415

  # ─── Public API ─────────────────────────────────────────────────────────────

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
    raise Error.new("common_name cannot be empty") if common_name.empty?
    raise Error.new("days must be positive") if days <= 0
    raise Error.new("ca_cert and ca_key must both be provided, or both omitted") if ca_cert.nil? != ca_key.nil?

    resolved_client_algo = client_algorithm || ca_algorithm

    if ca_cert && ca_key
      generate_ca_signed(common_name, days, resolved_client_algo, client_rsa_bits, ca_cert, ca_key)
    else
      generate_self_signed(common_name, days, ca_algorithm, ca_rsa_bits, resolved_client_algo, client_rsa_bits)
    end
  end

  # ─── Generation paths ────────────────────────────────────────────────────

  private def self.generate_self_signed(
    cn : String, days : Int32,
    ca_algo : Algorithm, ca_rsa_bits : Int32,
    client_algo : Algorithm, client_rsa_bits : Int32,
  ) : CertBundle
    validate_rsa_bits(ca_algo, ca_rsa_bits, "CA")
    validate_rsa_bits(client_algo, client_rsa_bits, "client")

    ca_pkey = gen_key(ca_algo, ca_rsa_bits)
    begin
      ca_cert_obj = build_ca_cert(cn, days, ca_pkey)

      client_pkey = gen_key(client_algo, client_rsa_bits)
      begin
        client_cert_obj = build_client_cert(cn, days, client_pkey, ca_cert_obj, ca_pkey)
        CertBundle.new(
          ca_cert:     cert_to_pem(ca_cert_obj),
          ca_key:      key_to_pkcs8_pem(ca_pkey),
          client_cert: cert_to_pem(client_cert_obj),
          client_key:  key_to_pkcs8_pem(client_pkey),
        )
      ensure
        LibX509Crypto.EVP_PKEY_free(client_pkey)
      end
    ensure
      LibX509Crypto.EVP_PKEY_free(ca_pkey)
    end
  end

  private def self.generate_ca_signed(
    cn : String, days : Int32,
    client_algo : Algorithm, client_rsa_bits : Int32,
    ca_cert_pem : String, ca_key_pem : String,
  ) : CertBundle
    validate_rsa_bits(client_algo, client_rsa_bits, "client")

    ca_cert_obj = parse_cert(ca_cert_pem)
    raise Error.new("Provided certificate is not a CA certificate") if LibX509Crypto.X509_check_ca(ca_cert_obj.to_unsafe) == 0

    ca_pkey = parse_key(ca_key_pem)
    begin
      raise Error.new("CA certificate and key do not match") unless keys_match?(ca_cert_obj, ca_pkey)

      client_pkey = gen_key(client_algo, client_rsa_bits)
      begin
        client_cert_obj = build_client_cert(cn, days, client_pkey, ca_cert_obj, ca_pkey)
        CertBundle.new(
          ca_cert:     ca_cert_pem,
          ca_key:      ca_key_pem,
          client_cert: cert_to_pem(client_cert_obj),
          client_key:  key_to_pkcs8_pem(client_pkey),
        )
      ensure
        LibX509Crypto.EVP_PKEY_free(client_pkey)
      end
    ensure
      LibX509Crypto.EVP_PKEY_free(ca_pkey)
    end
  end

  # ─── Key generation ──────────────────────────────────────────────────────

  private def self.gen_key(algo : Algorithm, rsa_bits : Int32) : Void*
    case algo
    when Algorithm::ECDSA
      ctx = LibX509Crypto.EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)
      raise Error.new("EVP_PKEY_CTX_new_id(EC) failed") if ctx.null?
      begin
        raise Error.new("EVP_PKEY_keygen_init failed") if LibX509Crypto.EVP_PKEY_keygen_init(ctx) != 1
        r = LibX509Crypto.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)
        raise Error.new("Setting EC P-256 curve failed (#{r})") if r <= 0
        pkey = Pointer(Void).null
        raise Error.new("EVP_PKEY_keygen(EC) failed") if LibX509Crypto.EVP_PKEY_keygen(ctx, pointerof(pkey)) != 1
        pkey
      ensure
        LibX509Crypto.EVP_PKEY_CTX_free(ctx)
      end
    else # RSA
      ctx = LibX509Crypto.EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil)
      raise Error.new("EVP_PKEY_CTX_new_id(RSA) failed") if ctx.null?
      begin
        raise Error.new("EVP_PKEY_keygen_init failed") if LibX509Crypto.EVP_PKEY_keygen_init(ctx) != 1
        r = LibX509Crypto.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits)
        raise Error.new("Setting RSA bits failed (#{r})") if r <= 0
        pkey = Pointer(Void).null
        raise Error.new("EVP_PKEY_keygen(RSA) failed") if LibX509Crypto.EVP_PKEY_keygen(ctx, pointerof(pkey)) != 1
        pkey
      ensure
        LibX509Crypto.EVP_PKEY_CTX_free(ctx)
      end
    end
  end

  # ─── Certificate building ────────────────────────────────────────────────

  private def self.build_ca_cert(cn : String, days : Int32, pkey : Void*) : OpenSSL::X509::Certificate
    cert = OpenSSL::X509::Certificate.new
    LibX509Crypto.X509_set_version(cert.to_unsafe, 2_i64)
    set_random_serial(cert)

    name = make_name(cn)
    cert.subject = name
    LibX509Crypto.X509_set_issuer_name(cert.to_unsafe, name.to_unsafe)

    set_validity(cert, days)
    LibX509Crypto.X509_set_pubkey(cert.to_unsafe, pkey)

    cert.add_extension(OpenSSL::X509::Extension.new("basicConstraints", "CA:TRUE,pathlen:1", true))
    cert.add_extension(OpenSSL::X509::Extension.new("keyUsage", "keyCertSign,cRLSign,digitalSignature", true))

    raise Error.new("X509_sign (CA) failed") if LibX509Crypto.X509_sign(cert.to_unsafe, pkey, LibCrypto.evp_sha256) == 0
    cert
  end

  private def self.build_client_cert(
    cn : String, days : Int32, client_pkey : Void*,
    ca_cert : OpenSSL::X509::Certificate, ca_pkey : Void*,
  ) : OpenSSL::X509::Certificate
    cert = OpenSSL::X509::Certificate.new
    LibX509Crypto.X509_set_version(cert.to_unsafe, 2_i64)
    set_random_serial(cert)

    cert.subject = make_name(cn)
    ca_subject = LibCrypto.x509_get_subject_name(ca_cert.to_unsafe)
    LibX509Crypto.X509_set_issuer_name(cert.to_unsafe, ca_subject)

    set_validity(cert, days)
    LibX509Crypto.X509_set_pubkey(cert.to_unsafe, client_pkey)

    cert.add_extension(OpenSSL::X509::Extension.new("basicConstraints", "CA:FALSE", false))
    cert.add_extension(OpenSSL::X509::Extension.new("keyUsage", "digitalSignature,keyEncipherment", true))
    cert.add_extension(OpenSSL::X509::Extension.new("extendedKeyUsage", "clientAuth", false))

    raise Error.new("X509_sign (client) failed") if LibX509Crypto.X509_sign(cert.to_unsafe, ca_pkey, LibCrypto.evp_sha256) == 0
    cert
  end

  # ─── PEM I/O ─────────────────────────────────────────────────────────────

  private def self.cert_to_pem(cert : OpenSSL::X509::Certificate) : String
    with_mem_bio do |bio|
      raise Error.new("PEM_write_bio_X509 failed") if LibX509Crypto.PEM_write_bio_X509(bio, cert.to_unsafe) != 1
      bio_read(bio)
    end
  end

  private def self.key_to_pkcs8_pem(pkey : Void*) : String
    with_mem_bio do |bio|
      r = LibX509Crypto.PEM_write_bio_PKCS8PrivateKey(bio, pkey, nil, nil, 0, nil, nil)
      raise Error.new("PEM_write_bio_PKCS8PrivateKey failed") if r != 1
      bio_read(bio)
    end
  end

  private def self.parse_cert(pem : String) : OpenSSL::X509::Certificate
    bio = LibX509Crypto.BIO_new_mem_buf(pem.to_unsafe, pem.bytesize)
    raise Error.new("BIO_new_mem_buf failed") if bio.null?
    begin
      raw = LibX509Crypto.PEM_read_bio_X509(bio, nil, nil, nil)
      raise Error.new("Failed to parse certificate PEM") if raw.null?
      begin
        OpenSSL::X509::Certificate.new(raw)
      ensure
        LibCrypto.x509_free(raw)
      end
    ensure
      LibCrypto.BIO_free(bio)
    end
  end

  private def self.parse_key(pem : String) : Void*
    bio = LibX509Crypto.BIO_new_mem_buf(pem.to_unsafe, pem.bytesize)
    raise Error.new("BIO_new_mem_buf failed") if bio.null?
    begin
      pkey = LibX509Crypto.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
      raise Error.new("Failed to parse private key PEM") if pkey.null?
      pkey
    ensure
      LibCrypto.BIO_free(bio)
    end
  end

  # ─── Helpers ─────────────────────────────────────────────────────────────

  private def self.make_name(cn : String) : OpenSSL::X509::Name
    name = OpenSSL::X509::Name.new
    name.add_entry("CN", cn)
    name.add_entry("O", "x509-crystal")
    name
  end

  private def self.set_random_serial(cert : OpenSSL::X509::Certificate)
    bn = LibX509Crypto.BN_new
    raise Error.new("BN_new failed") if bn.null?
    begin
      raise Error.new("BN_rand failed") if LibX509Crypto.BN_rand(bn, 128, -1, 0) != 1
      ai = LibX509Crypto.BN_to_ASN1_INTEGER(bn, nil)
      raise Error.new("BN_to_ASN1_INTEGER failed") if ai.null?
      begin
        LibX509Crypto.X509_set_serialNumber(cert.to_unsafe, ai)
      ensure
        LibX509Crypto.ASN1_INTEGER_free(ai)
      end
    ensure
      LibX509Crypto.BN_free(bn)
    end
  end

  private def self.set_validity(cert : OpenSSL::X509::Certificate, days : Int32)
    LibX509Crypto.X509_gmtime_adj(LibX509Crypto.X509_getm_notBefore(cert.to_unsafe), -60_i64)
    LibX509Crypto.X509_gmtime_adj(LibX509Crypto.X509_getm_notAfter(cert.to_unsafe), days.to_i64 * 86400_i64)
  end

  private def self.keys_match?(cert : OpenSSL::X509::Certificate, pkey : Void*) : Bool
    cert_pub = LibX509Crypto.X509_get0_pubkey(cert.to_unsafe)
    return false if cert_pub.null?
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
      LibX509Crypto.EVP_PKEY_eq(cert_pub, pkey) == 1
    {% else %}
      LibX509Crypto.EVP_PKEY_cmp(cert_pub, pkey) == 1
    {% end %}
  end

  private def self.validate_rsa_bits(algo : Algorithm, bits : Int32, role : String)
    return unless algo == Algorithm::RSA
    raise Error.new("RSA #{role} key bits must be >= 2048") if bits < 2048
  end

  private def self.with_mem_bio(&)
    bio = LibCrypto.BIO_new(LibX509Crypto.BIO_s_mem)
    raise Error.new("BIO_new failed") if bio.null?
    begin
      yield bio
    ensure
      LibCrypto.BIO_free(bio)
    end
  end

  private def self.bio_read(bio : LibCrypto::Bio*) : String
    out = IO::Memory.new
    chunk = Bytes.new(4096)
    while (n = LibX509Crypto.BIO_read(bio, chunk.to_unsafe, chunk.size)) > 0
      out.write(chunk[0, n])
    end
    out.to_s
  end
end
