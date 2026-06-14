# x509-crystal

Pure Crystal X.509 certificate generation. Generates self-signed and CA-signed certificate bundles for mTLS and PKI use cases. Supports ECDSA P-256 and RSA via direct `LibCrypto` bindings — no Go toolchain, no external tools.

## What it does

Fills the gap in Crystal's stdlib: the OpenSSL bindings cover TLS but not certificate *generation*. This shard adds `X509.generate` which produces a ready-to-use `CertBundle` (CA cert + CA key + client cert + client key).

## Language / stack

- Crystal >= 1.20.0
- Direct `LibCrypto` bindings (no shard dependencies beyond ameba for linting)
- OpenSSL (system library)

## Key entry points

| File | Purpose |
|------|---------|
| `src/x509/lib_x509.cr` | Raw `LibCrypto` bindings |
| `src/x509/algorithm.cr` | `X509::Algorithm` enum (ECDSA, RSA) |
| `src/x509/cert_bundle.cr` | `X509::CertBundle` struct (ca_cert, ca_key, client_cert, client_key — all PEM strings) |
| `src/x509.cr` | `X509.generate(...)` — public API |

## Public API

```crystal
# Self-signed (dev/test)
bundle = X509.generate(common_name: "tenant-abc123", days: 3650)

# CA-signed (production — bring your own CA)
bundle = X509.generate(
  common_name: "tenant-abc123",
  days: 3650,
  ca_cert: File.read("my-ca.crt"),
  ca_key:  File.read("my-ca.key"),
)

# RSA
bundle = X509.generate(
  common_name: "tenant-abc123", days: 3650,
  ca_algorithm: X509::Algorithm::RSA, client_algorithm: X509::Algorithm::RSA,
  ca_rsa_bits: 4096, client_rsa_bits: 4096,
)
```

All errors raise `X509::Error`.

## Build & test

```sh
shards install
crystal spec
bin/ameba src/
```

## Used by

`dirless-cli` — generates the CA + client cert bundle during node enrollment and writes it to `/etc/dirless/`.
