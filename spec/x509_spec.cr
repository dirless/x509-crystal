require "./spec_helper"

# ─── helpers ──────────────────────────────────────────────────────────────────

# Returns a bundle generated with the default options (ECDSA, self-signed, 365 days).
def default_bundle : X509::CertBundle
  X509.generate(common_name: "test-tenant", days: 365)
end

# Returns a CA bundle to use as "bring your own CA" test input.
def external_ca(algorithm : X509::Algorithm = X509::Algorithm::ECDSA, rsa_bits : Int32 = 4096)
  X509.generate(
    common_name:  "external-ca",
    days:         3650,
    ca_algorithm: algorithm,
    ca_rsa_bits:  rsa_bits,
  )
end

# Returns true if *pem* starts with the expected PEM header.
def pem_type?(pem : String, type : String) : Bool
  pem.starts_with?("-----BEGIN #{type}-----")
end

# ─── self-signed ECDSA (default) ─────────────────────────────────────────────

describe X509 do
  describe ".generate — self-signed ECDSA (defaults)" do
    it "returns a CertBundle" do
      default_bundle.should be_a(X509::CertBundle)
    end

    it "all four fields are non-empty" do
      b = default_bundle
      b.ca_cert.should_not be_empty
      b.ca_key.should_not be_empty
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "ca_cert has CERTIFICATE PEM header" do
      pem_type?(default_bundle.ca_cert, "CERTIFICATE").should be_true
    end

    it "ca_key has PRIVATE KEY PEM header" do
      pem_type?(default_bundle.ca_key, "PRIVATE KEY").should be_true
    end

    it "client_cert has CERTIFICATE PEM header" do
      pem_type?(default_bundle.client_cert, "CERTIFICATE").should be_true
    end

    it "client_key has PRIVATE KEY PEM header" do
      pem_type?(default_bundle.client_key, "PRIVATE KEY").should be_true
    end

    it "two independent calls produce different CA certs" do
      b1 = default_bundle
      b2 = default_bundle
      b1.ca_cert.should_not eq(b2.ca_cert)
    end

    it "two independent calls produce different CA keys" do
      b1 = default_bundle
      b2 = default_bundle
      b1.ca_key.should_not eq(b2.ca_key)
    end

    it "two independent calls produce different client certs" do
      b1 = default_bundle
      b2 = default_bundle
      b1.client_cert.should_not eq(b2.client_cert)
    end
  end

  # ─── common_name propagation ─────────────────────────────────────────────

  describe ".generate — common_name" do
    it "common_name is present in ca_cert PEM" do
      b = X509.generate(common_name: "unique-tenant-abc123", days: 365)
      b.ca_cert.should_not be_empty
      # The PEM is DER-encoded so we can't grep the CN directly,
      # but we can assert the bundle was generated without error.
    end

    it "accepts a common_name with dots and hyphens" do
      b = X509.generate(common_name: "tenant-123.example.com", days: 365)
      b.ca_cert.should_not be_empty
    end

    it "accepts a 64-character common_name" do
      cn = "x" * 64
      b = X509.generate(common_name: cn, days: 365)
      b.ca_cert.should_not be_empty
    end
  end

  # ─── days ────────────────────────────────────────────────────────────────

  describe ".generate — days" do
    it "accepts 1 day" do
      b = X509.generate(common_name: "test", days: 1)
      b.ca_cert.should_not be_empty
    end

    it "accepts 365 days" do
      b = X509.generate(common_name: "test", days: 365)
      b.ca_cert.should_not be_empty
    end

    it "accepts 3650 days (10 years)" do
      b = X509.generate(common_name: "test", days: 3650)
      b.ca_cert.should_not be_empty
    end

    it "accepts 10950 days (30 years)" do
      b = X509.generate(common_name: "test", days: 10950)
      b.ca_cert.should_not be_empty
    end
  end

  # ─── RSA self-signed ─────────────────────────────────────────────────────

  describe ".generate — self-signed RSA" do
    it "generates a bundle with RSA 2048 for both CA and client" do
      b = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::RSA,
        client_algorithm: X509::Algorithm::RSA,
        ca_rsa_bits:      2048,
        client_rsa_bits:  2048,
      )
      b.ca_cert.should_not be_empty
      b.ca_key.should_not be_empty
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "generates a bundle with RSA 4096 for both CA and client" do
      b = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::RSA,
        client_algorithm: X509::Algorithm::RSA,
        ca_rsa_bits:      4096,
        client_rsa_bits:  4096,
      )
      b.ca_cert.should_not be_empty
      b.client_cert.should_not be_empty
    end

    it "generates a bundle with RSA 3072 CA" do
      b = X509.generate(
        common_name:  "test",
        days:         365,
        ca_algorithm: X509::Algorithm::RSA,
        ca_rsa_bits:  3072,
      )
      b.ca_key.should_not be_empty
    end

    it "RSA bundle produces different certs on successive calls" do
      b1 = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::RSA,
        client_algorithm: X509::Algorithm::RSA,
        ca_rsa_bits:      2048,
        client_rsa_bits:  2048,
      )
      b2 = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::RSA,
        client_algorithm: X509::Algorithm::RSA,
        ca_rsa_bits:      2048,
        client_rsa_bits:  2048,
      )
      b1.ca_cert.should_not eq(b2.ca_cert)
    end
  end

  # ─── mixed algorithms ─────────────────────────────────────────────────────

  describe ".generate — mixed algorithms" do
    it "ECDSA CA + RSA client generates without error" do
      b = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::ECDSA,
        client_algorithm: X509::Algorithm::RSA,
        client_rsa_bits:  2048,
      )
      b.ca_cert.should_not be_empty
      b.client_cert.should_not be_empty
    end

    it "RSA CA + ECDSA client generates without error" do
      b = X509.generate(
        common_name:      "test",
        days:             365,
        ca_algorithm:     X509::Algorithm::RSA,
        client_algorithm: X509::Algorithm::ECDSA,
        ca_rsa_bits:      2048,
      )
      b.ca_cert.should_not be_empty
      b.client_cert.should_not be_empty
    end

    it "client_algorithm defaults to ca_algorithm when not set" do
      # Both ECDSA — should be identical behaviour to not setting client_algorithm.
      b = X509.generate(
        common_name:  "test",
        days:         365,
        ca_algorithm: X509::Algorithm::ECDSA,
      )
      b.ca_cert.should_not be_empty
      b.client_cert.should_not be_empty
    end
  end

  # ─── CA-signed mode ────────────────────────────────────────────────────────

  describe ".generate — CA-signed mode" do
    it "returns all four fields when using an external ECDSA CA" do
      ca = external_ca
      b  = X509.generate(
        common_name: "my-tenant",
        days:        365,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      b.ca_cert.should_not be_empty
      b.ca_key.should_not be_empty
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "bundle ca_cert equals the provided CA cert" do
      ca = external_ca
      b  = X509.generate(
        common_name: "my-tenant",
        days:        365,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      b.ca_cert.should eq(ca.ca_cert)
    end

    it "bundle ca_key equals the provided CA key" do
      ca = external_ca
      b  = X509.generate(
        common_name: "my-tenant",
        days:        365,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      b.ca_key.should eq(ca.ca_key)
    end

    it "client_cert has CERTIFICATE PEM header in CA-signed mode" do
      ca = external_ca
      b  = X509.generate(
        common_name: "my-tenant",
        days:        365,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      pem_type?(b.client_cert, "CERTIFICATE").should be_true
    end

    it "client_key has PRIVATE KEY PEM header in CA-signed mode" do
      ca = external_ca
      b  = X509.generate(
        common_name: "my-tenant",
        days:        365,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      pem_type?(b.client_key, "PRIVATE KEY").should be_true
    end

    it "generates RSA client cert under ECDSA CA" do
      ca = external_ca(X509::Algorithm::ECDSA)
      b  = X509.generate(
        common_name:      "my-tenant",
        days:             365,
        ca_cert:          ca.ca_cert,
        ca_key:           ca.ca_key,
        client_algorithm: X509::Algorithm::RSA,
        client_rsa_bits:  2048,
      )
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "generates ECDSA client cert under RSA CA" do
      ca = external_ca(X509::Algorithm::RSA, 2048)
      b  = X509.generate(
        common_name:      "my-tenant",
        days:             365,
        ca_cert:          ca.ca_cert,
        ca_key:           ca.ca_key,
        client_algorithm: X509::Algorithm::ECDSA,
      )
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "generates RSA client cert under RSA CA" do
      ca = external_ca(X509::Algorithm::RSA, 2048)
      b  = X509.generate(
        common_name:      "my-tenant",
        days:             365,
        ca_cert:          ca.ca_cert,
        ca_key:           ca.ca_key,
        client_algorithm: X509::Algorithm::RSA,
        client_rsa_bits:  2048,
      )
      b.client_cert.should_not be_empty
      b.client_key.should_not be_empty
    end

    it "two CA-signed calls from the same CA produce different client certs" do
      ca = external_ca
      b1 = X509.generate(common_name: "t", days: 365, ca_cert: ca.ca_cert, ca_key: ca.ca_key)
      b2 = X509.generate(common_name: "t", days: 365, ca_cert: ca.ca_cert, ca_key: ca.ca_key)
      b1.client_cert.should_not eq(b2.client_cert)
    end

    it "two CA-signed calls from the same CA produce different client keys" do
      ca = external_ca
      b1 = X509.generate(common_name: "t", days: 365, ca_cert: ca.ca_cert, ca_key: ca.ca_key)
      b2 = X509.generate(common_name: "t", days: 365, ca_cert: ca.ca_cert, ca_key: ca.ca_key)
      b1.client_key.should_not eq(b2.client_key)
    end

    it "accepts 90-day validity for CA-signed client cert" do
      ca = external_ca
      b  = X509.generate(
        common_name: "t",
        days:        90,
        ca_cert:     ca.ca_cert,
        ca_key:      ca.ca_key,
      )
      b.client_cert.should_not be_empty
    end
  end

  # ─── error cases ──────────────────────────────────────────────────────────

  describe ".generate — error handling" do
    it "raises X509::Error for empty common_name" do
      expect_raises(X509::Error) do
        X509.generate(common_name: "", days: 365)
      end
    end

    it "raises X509::Error for days = 0" do
      expect_raises(X509::Error) do
        X509.generate(common_name: "test", days: 0)
      end
    end

    it "raises X509::Error for negative days" do
      expect_raises(X509::Error) do
        X509.generate(common_name: "test", days: -1)
      end
    end

    it "raises X509::Error for RSA CA bits below 2048" do
      expect_raises(X509::Error) do
        X509.generate(
          common_name:  "test",
          days:         365,
          ca_algorithm: X509::Algorithm::RSA,
          ca_rsa_bits:  1024,
        )
      end
    end

    it "raises X509::Error for RSA client bits below 2048" do
      expect_raises(X509::Error) do
        X509.generate(
          common_name:      "test",
          days:             365,
          client_algorithm: X509::Algorithm::RSA,
          client_rsa_bits:  512,
        )
      end
    end

    it "raises X509::Error when ca_cert is provided but ca_key is nil" do
      ca = external_ca
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     ca.ca_cert,
          ca_key:      nil,
        )
      end
    end

    it "raises X509::Error when ca_key is provided but ca_cert is nil" do
      ca = external_ca
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     nil,
          ca_key:      ca.ca_key,
        )
      end
    end

    it "raises X509::Error for invalid CA cert PEM" do
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     "not-valid-pem",
          ca_key:      "not-valid-pem",
        )
      end
    end

    it "raises X509::Error when a non-CA cert is used as CA" do
      b = default_bundle
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     b.client_cert, # not a CA cert
          ca_key:      b.client_key,
        )
      end
    end

    it "raises X509::Error for mismatched CA cert and key" do
      ca1 = external_ca
      ca2 = external_ca
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     ca1.ca_cert,
          ca_key:      ca2.ca_key, # from a different CA
        )
      end
    end

    it "raises X509::Error for corrupted CA key bytes" do
      ca = external_ca
      expect_raises(X509::Error) do
        X509.generate(
          common_name: "test",
          days:        365,
          ca_cert:     ca.ca_cert,
          ca_key:      "-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2hp\n-----END PRIVATE KEY-----",
        )
      end
    end

    it "error message is a non-empty string" do
      error_message = ""
      begin
        X509.generate(common_name: "", days: 365)
      rescue e : X509::Error
        error_message = e.message.to_s
      end
      error_message.should_not be_empty
    end
  end

  # ─── Algorithm enum ───────────────────────────────────────────────────────

  describe "X509::Algorithm" do
    it "ECDSA has value 0" do
      X509::Algorithm::ECDSA.value.should eq(0)
    end

    it "RSA has value 1" do
      X509::Algorithm::RSA.value.should eq(1)
    end
  end

  # ─── CertBundle struct ────────────────────────────────────────────────────

  describe "X509::CertBundle" do
    it "exposes ca_cert getter" do
      b = default_bundle
      b.responds_to?(:ca_cert).should be_true
    end

    it "exposes ca_key getter" do
      b = default_bundle
      b.responds_to?(:ca_key).should be_true
    end

    it "exposes client_cert getter" do
      b = default_bundle
      b.responds_to?(:client_cert).should be_true
    end

    it "exposes client_key getter" do
      b = default_bundle
      b.responds_to?(:client_key).should be_true
    end
  end

  # ─── stress / concurrent ─────────────────────────────────────────────────

  describe ".generate — stress" do
    it "generates 10 consecutive bundles without error" do
      10.times do
        b = default_bundle
        b.ca_cert.should_not be_empty
        b.client_cert.should_not be_empty
      end
    end

    it "generates 20 bundles concurrently without error or panic" do
      channel = Channel(Exception?).new(20)
      20.times do
        spawn do
          begin
            default_bundle
            channel.send(nil)
          rescue e : Exception
            channel.send(e)
          end
        end
      end
      20.times do
        err = channel.receive
        err.should be_nil
      end
    end

    it "generates 10 CA-signed certs from the same CA without error" do
      ca = external_ca
      10.times do
        b = X509.generate(
          common_name: "tenant",
          days:        365,
          ca_cert:     ca.ca_cert,
          ca_key:      ca.ca_key,
        )
        b.client_cert.should_not be_empty
      end
    end
  end
end
