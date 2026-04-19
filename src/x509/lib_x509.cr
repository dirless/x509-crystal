require "openssl"

# Additional LibCrypto bindings needed for pure-Crystal X.509 generation.
# BIO_new and BIO_free are already declared in Crystal's LibCrypto; everything
# else here is absent from the stdlib's TLS-consumer subset.
@[Link("crypto")]
lib LibX509Crypto
  # ── BIO memory ────────────────────────────────────────────────────────────
  # BIO_new / BIO_free → use LibCrypto.BIO_new / LibCrypto.BIO_free
  fun BIO_s_mem : LibCrypto::BioMethod*
  fun BIO_new_mem_buf(buf : UInt8*, len : Int32) : LibCrypto::Bio*
  fun BIO_read(bio : LibCrypto::Bio*, buf : UInt8*, len : Int32) : Int32

  # ── PEM I/O ──────────────────────────────────────────────────────────────
  fun PEM_write_bio_X509(bio : LibCrypto::Bio*, x509 : LibCrypto::X509) : Int32
  fun PEM_write_bio_PKCS8PrivateKey(bio : LibCrypto::Bio*, pkey : Void*, enc : Void*,
                                    kstr : UInt8*, klen : Int32,
                                    cb : Void*, u : Void*) : Int32
  fun PEM_read_bio_X509(bio : LibCrypto::Bio*, x : LibCrypto::X509*,
                        cb : Void*, u : Void*) : LibCrypto::X509
  fun PEM_read_bio_PrivateKey(bio : LibCrypto::Bio*, x : Void**,
                              cb : Void*, u : Void*) : Void*

  # ── EVP_PKEY key generation ───────────────────────────────────────────────
  fun EVP_PKEY_free(pkey : Void*)
  fun EVP_PKEY_CTX_new_id(id : Int32, e : Void*) : Void*
  fun EVP_PKEY_CTX_free(ctx : Void*)
  fun EVP_PKEY_keygen_init(ctx : Void*) : Int32
  fun EVP_PKEY_keygen(ctx : Void*, ppkey : Void**) : Int32
  # In OpenSSL 3.0+ these are real functions; in 1.1.x they expand to
  # EVP_PKEY_CTX_ctrl calls.  We bind as real functions (OpenSSL 3+ only).
  fun EVP_PKEY_CTX_set_rsa_keygen_bits(ctx : Void*, bits : Int32) : Int32
  fun EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx : Void*, nid : Int32) : Int32

  # ── X.509 certificate building ────────────────────────────────────────────
  fun X509_set_version(cert : LibCrypto::X509, version : Int64) : Int32
  fun X509_set_issuer_name(cert : LibCrypto::X509, name : LibCrypto::X509_NAME) : Int32
  fun X509_set_pubkey(cert : LibCrypto::X509, pkey : Void*) : Int32
  fun X509_sign(cert : LibCrypto::X509, pkey : Void*, md : LibCrypto::EVP_MD) : Int32
  fun X509_check_ca(cert : LibCrypto::X509) : Int32
  fun X509_get0_pubkey(cert : LibCrypto::X509) : Void*

  # ── Validity period ────────────────────────────────────────────────────────
  fun X509_getm_notBefore(cert : LibCrypto::X509) : Void*
  fun X509_getm_notAfter(cert : LibCrypto::X509) : Void*
  fun X509_gmtime_adj(tm : Void*, adj : Int64) : Void*

  # ── Serial number (BigNum → ASN1_INTEGER) ─────────────────────────────────
  fun BN_new : Void*
  fun BN_free(bn : Void*)
  fun BN_rand(rnd : Void*, bits : Int32, top : Int32, bottom : Int32) : Int32
  fun BN_to_ASN1_INTEGER(bn : Void*, ai : Void*) : Void*
  fun ASN1_INTEGER_free(ai : Void*)
  fun X509_set_serialNumber(cert : LibCrypto::X509, serial : Void*) : Int32
  # X509_NAME_add_entry_by_NID with V_ASN1_UTF8STRING (12) instead of
  # MBSTRING_UTF8 bypasses the RFC 5280 ub-common-name 64-char limit that
  # OpenSSL 3.x enforces when using the MBSTRING auto-selection path.
  fun X509_NAME_add_entry_by_NID(name : LibCrypto::X509_NAME, nid : Int32,
                                  type : Int32, bytes : UInt8*, len : Int32,
                                  loc : Int32, set : Int32) : Int32

  # ── Key-matches-cert check ────────────────────────────────────────────────
  {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
    fun EVP_PKEY_eq(a : Void*, b : Void*) : Int32
  {% else %}
    fun EVP_PKEY_cmp(a : Void*, b : Void*) : Int32
  {% end %}
end
