# x509-crystal

Pure Crystal X.509 certificate generation using OpenSSL (already a Crystal stdlib
dependency — no extra native libraries required).

Generates self-signed and CA-signed X.509 certificates for mTLS and PKI use cases,
with support for ECDSA P-256 and RSA at user-specified key sizes.

## Why

Crystal's standard library ships with OpenSSL bindings for TLS, but doesn't expose
the certificate *generation* surface. This shard adds the missing pieces via direct
`LibCrypto` bindings — no Go toolchain, no CGo, no shared library to manage.

## Requirements

- Crystal >= 1.20.0
- OpenSSL (already linked by Crystal — no extra setup)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  x509-crystal:
    github: dirless/x509-crystal
```

Run `shards install`. That's it — no native library to build or copy.

## Usage

```crystal
require "x509-crystal"

# Self-signed (testing / development)
bundle = X509.generate(common_name: "tenant-abc123", days: 3650)

bundle.ca_cert     # String (PEM) — self-signed CA certificate
bundle.ca_key      # String (PEM) — CA private key (PKCS8)
bundle.client_cert # String (PEM) — client cert signed by the CA
bundle.client_key  # String (PEM) — client private key (PKCS8)

# CA-signed (production — bring your own CA)
bundle = X509.generate(
  common_name: "tenant-abc123",
  days:        3650,
  ca_cert:     File.read("my-ca.crt"),
  ca_key:      File.read("my-ca.key"),
)
# bundle.ca_cert / bundle.ca_key echo back the values you provided
# bundle.client_cert / bundle.client_key are freshly generated

# RSA instead of the default ECDSA
bundle = X509.generate(
  common_name:      "tenant-abc123",
  days:             3650,
  ca_algorithm:     X509::Algorithm::RSA,
  client_algorithm: X509::Algorithm::RSA,
  ca_rsa_bits:      4096,
  client_rsa_bits:  4096,
)

# Mixed algorithms — ECDSA CA with RSA client cert (or vice versa)
bundle = X509.generate(
  common_name:      "tenant-abc123",
  days:             3650,
  ca_algorithm:     X509::Algorithm::ECDSA,
  client_algorithm: X509::Algorithm::RSA,
  client_rsa_bits:  2048,
)
```

## API

### `X509.generate`

```crystal
X509.generate(
  common_name      : String,
  days             : Int32,
  ca_algorithm     : X509::Algorithm = X509::Algorithm::ECDSA,
  client_algorithm : X509::Algorithm? = nil,    # defaults to ca_algorithm
  ca_rsa_bits      : Int32 = 4096,
  client_rsa_bits  : Int32 = 4096,
  ca_cert          : String? = nil,             # omit for self-signed mode
  ca_key           : String? = nil,
) : X509::CertBundle
```

Raises `X509::Error` on failure.

**`days`** applies to both the CA and client cert in self-signed mode. In CA-signed
mode it only affects the client cert — the provided CA's validity is already fixed.

**`client_algorithm`** defaults to `ca_algorithm` when not set, so both certs use
the same algorithm unless you explicitly override it.

### `X509::Algorithm`

```crystal
X509::Algorithm::ECDSA  # P-256 (default)
X509::Algorithm::RSA    # RSA with user-specified bit size
```

### `X509::CertBundle`

```crystal
bundle.ca_cert     : String  # PEM-encoded CA certificate
bundle.ca_key      : String  # PEM-encoded CA private key (PKCS8)
bundle.client_cert : String  # PEM-encoded client certificate
bundle.client_key  : String  # PEM-encoded client private key (PKCS8)
```

## Error handling

All errors raise `X509::Error` with a descriptive message. Common causes:

- Empty `common_name`
- Non-positive `days`
- RSA `*_rsa_bits` below 2048
- Invalid or non-CA cert provided as `ca_cert`
- Mismatched `ca_cert` and `ca_key`
- Only one of `ca_cert` / `ca_key` provided (both or neither)

## Testing

```sh
crystal spec
```

## License

MIT
