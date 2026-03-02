# x509-crystal

Crystal bindings to Go's `crypto/x509` standard library via a shared library.

Generates self-signed and CA-signed X.509 certificates for mTLS and PKI use cases,
with support for ECDSA P-256 and RSA at user-specified key sizes.

## Why

Go's `crypto/x509` package is a mature, well-audited implementation of the X.509
standard maintained by the Go team. Rather than reimplement certificate generation
in Crystal, we wrap it via CGo FFI — the same pattern used by
[age-crystal](https://github.com/dirless/age-crystal).

The result is zero external dependencies on the Go side (pure standard library),
and a clean idiomatic Crystal API on the consumer side.

## Requirements

- Crystal >= 1.9.0
- `libx509.so` — prebuilt and shipped with releases (see below)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  x509-crystal:
    github: dirless/x509-crystal
```

Copy `libx509.so` to a location on your library path (e.g. `/usr/lib/`) or
alongside your binary.

### Building `libx509.so` from source

For local development (requires Go >= 1.21 on PATH):

```sh
make build
# → libx509.so
```

For a production-compatible build matching the RPM target (requires Docker):

```sh
make docker-build
# → dist/libx509.so (built inside Amazon Linux 2023)
```

Use `dist/libx509.so` for anything going into an RPM.

## Usage

```crystal
require "x509-crystal"

# Self-signed (testing / development)
bundle = X509.generate(common_name: "tenant-abc123", days: 3650)

bundle.ca_cert     # String (PEM) — self-signed CA certificate
bundle.ca_key      # String (PEM) — CA private key
bundle.client_cert # String (PEM) — client cert signed by the CA
bundle.client_key  # String (PEM) — client private key

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

## Error Handling

All errors raise `X509::Error` with a descriptive message. Common causes:

- Empty `common_name`
- Non-positive `days`
- RSA `*_rsa_bits` below 2048
- Invalid or non-CA cert provided as `ca_cert`
- Mismatched `ca_cert` and `ca_key`
- Only one of `ca_cert` / `ca_key` provided (both or neither)

## Testing

```sh
# Go unit tests (no shared library needed)
make test-go

# Crystal specs (builds libx509.so first)
make test-crystal

# Both
make test
```

## License

MIT
