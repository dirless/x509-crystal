package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func parsePEMCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func parsePEMKey(t *testing.T, pemStr string) any {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	return key
}

func assertNonEmpty(t *testing.T, label, s string) {
	t.Helper()
	if strings.TrimSpace(s) == "" {
		t.Errorf("%s is empty", label)
	}
}

func assertPEMType(t *testing.T, label, pemStr, want string) {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("%s: could not decode PEM", label)
	}
	if block.Type != want {
		t.Errorf("%s: PEM type want %q, got %q", label, want, block.Type)
	}
}

func assertRSABits(t *testing.T, label, keyPEM string, wantBits int) {
	t.Helper()
	key := parsePEMKey(t, keyPEM)
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("%s key: want *rsa.PrivateKey, got %T", label, key)
		return
	}
	if rsaKey.N.BitLen() != wantBits {
		t.Errorf("%s key: want %d bits, got %d", label, wantBits, rsaKey.N.BitLen())
	}
}

func verifyClientAgainstCA(t *testing.T, caCertPEM, clientCertPEM string) {
	t.Helper()
	caCert := parsePEMCert(t, caCertPEM)
	clientCert := parsePEMCert(t, clientCertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert should verify against CA: %v", err)
	}
}

// defaultOpts returns minimal valid GenerateOptions (ECDSA self-signed).
func defaultOpts() GenerateOptions {
	return GenerateOptions{
		CommonName:    "test-tenant",
		Days:          365,
		CAAlgo:        AlgoECDSA,
		ClientAlgo:    AlgoECDSA,
		CARSABits:     4096,
		ClientRSABits: 4096,
	}
}

// externalCA generates a CA bundle to use as "bring your own CA" test input.
func externalCA(t *testing.T, algo, rsaBits int) (certPEM, keyPEM string) {
	t.Helper()
	o := defaultOpts()
	o.CommonName = "external-ca"
	o.Days = 3650
	o.CAAlgo = algo
	o.CARSABits = rsaBits
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("failed to generate external CA: %v", err)
	}
	return b.CACert, b.CAKey
}

// ─── self-signed ECDSA (default) ─────────────────────────────────────────────

func TestSelfSigned_ECDSA_AllFieldsPopulated(t *testing.T) {
	b, err := Generate(defaultOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNonEmpty(t, "ca_cert", b.CACert)
	assertNonEmpty(t, "ca_key", b.CAKey)
	assertNonEmpty(t, "client_cert", b.ClientCert)
	assertNonEmpty(t, "client_key", b.ClientKey)
}

func TestSelfSigned_ECDSA_PEMHeaders(t *testing.T) {
	b, err := Generate(defaultOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertPEMType(t, "ca_cert", b.CACert, "CERTIFICATE")
	assertPEMType(t, "ca_key", b.CAKey, "PRIVATE KEY")
	assertPEMType(t, "client_cert", b.ClientCert, "CERTIFICATE")
	assertPEMType(t, "client_key", b.ClientKey, "PRIVATE KEY")
}

func TestSelfSigned_ECDSA_CAIsMarkedAsCA(t *testing.T) {
	b, _ := Generate(defaultOpts())
	cert := parsePEMCert(t, b.CACert)
	if !cert.IsCA {
		t.Error("CA cert: IsCA should be true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert: should have KeyUsageCertSign")
	}
}

func TestSelfSigned_ECDSA_ClientIsNotCA(t *testing.T) {
	b, _ := Generate(defaultOpts())
	if parsePEMCert(t, b.ClientCert).IsCA {
		t.Error("client cert: IsCA should be false")
	}
}

func TestSelfSigned_ECDSA_ClientHasClientAuthEKU(t *testing.T) {
	b, _ := Generate(defaultOpts())
	cert := parsePEMCert(t, b.ClientCert)
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return
		}
	}
	t.Error("client cert: missing ExtKeyUsageClientAuth")
}

func TestSelfSigned_ECDSA_ClientLacksServerAuthEKU(t *testing.T) {
	b, _ := Generate(defaultOpts())
	cert := parsePEMCert(t, b.ClientCert)
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Error("client cert should NOT have ExtKeyUsageServerAuth")
			return
		}
	}
}

func TestSelfSigned_ECDSA_CommonNamePropagatedToCA(t *testing.T) {
	o := defaultOpts()
	o.CommonName = "unique-tenant-abc123"
	b, _ := Generate(o)
	if got := parsePEMCert(t, b.CACert).Subject.CommonName; got != o.CommonName {
		t.Errorf("CA CN: want %q, got %q", o.CommonName, got)
	}
}

func TestSelfSigned_ECDSA_CommonNamePropagatedToClient(t *testing.T) {
	o := defaultOpts()
	o.CommonName = "unique-tenant-abc123"
	b, _ := Generate(o)
	if got := parsePEMCert(t, b.ClientCert).Subject.CommonName; got != o.CommonName {
		t.Errorf("client CN: want %q, got %q", o.CommonName, got)
	}
}

func TestSelfSigned_ECDSA_ValidityPeriodCA(t *testing.T) {
	o := defaultOpts()
	o.Days = 730
	b, _ := Generate(o)
	cert := parsePEMCert(t, b.CACert)
	expected := time.Duration(o.Days) * 24 * time.Hour
	got := cert.NotAfter.Sub(cert.NotBefore)
	if diff := got - expected; diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("CA validity: want ~%v, got %v", expected, got)
	}
}

func TestSelfSigned_ECDSA_ValidityPeriodClient(t *testing.T) {
	o := defaultOpts()
	o.Days = 730
	b, _ := Generate(o)
	cert := parsePEMCert(t, b.ClientCert)
	expected := time.Duration(o.Days) * 24 * time.Hour
	got := cert.NotAfter.Sub(cert.NotBefore)
	if diff := got - expected; diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("client validity: want ~%v, got %v", expected, got)
	}
}

func TestSelfSigned_ECDSA_CertsAreCurrentlyValid(t *testing.T) {
	b, _ := Generate(defaultOpts())
	now := time.Now()
	for _, tc := range []struct{ name, pem string }{{"ca", b.CACert}, {"client", b.ClientCert}} {
		cert := parsePEMCert(t, tc.pem)
		if now.Before(cert.NotBefore) {
			t.Errorf("%s: NotBefore %v is in the future", tc.name, cert.NotBefore)
		}
		if now.After(cert.NotAfter) {
			t.Errorf("%s: NotAfter %v is in the past", tc.name, cert.NotAfter)
		}
	}
}

func TestSelfSigned_ECDSA_CAIsSelfSigned(t *testing.T) {
	b, _ := Generate(defaultOpts())
	cert := parsePEMCert(t, b.CACert)
	if cert.Issuer.CommonName != cert.Subject.CommonName {
		t.Errorf("CA: issuer %q should equal subject %q",
			cert.Issuer.CommonName, cert.Subject.CommonName)
	}
}

func TestSelfSigned_ECDSA_ClientSignedByCA(t *testing.T) {
	b, _ := Generate(defaultOpts())
	verifyClientAgainstCA(t, b.CACert, b.ClientCert)
}

func TestSelfSigned_ECDSA_ClientDoesNotVerifyUnderWrongCA(t *testing.T) {
	b1, _ := Generate(defaultOpts())
	b2, _ := Generate(defaultOpts())
	ca2 := parsePEMCert(t, b2.CACert)
	client1 := parsePEMCert(t, b1.ClientCert)
	pool := x509.NewCertPool()
	pool.AddCert(ca2)
	_, err := client1.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Error("client from bundle 1 should NOT verify under CA from bundle 2")
	}
}

func TestSelfSigned_ECDSA_KeysAreP256(t *testing.T) {
	b, _ := Generate(defaultOpts())
	for _, tc := range []struct{ name, pem string }{{"ca", b.CAKey}, {"client", b.ClientKey}} {
		key := parsePEMKey(t, tc.pem)
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("%s key: want *ecdsa.PrivateKey, got %T", tc.name, key)
			continue
		}
		if ecKey.Curve != elliptic.P256() {
			t.Errorf("%s key: want P-256, got %v", tc.name, ecKey.Curve)
		}
	}
}

func TestSelfSigned_ECDSA_CAAndClientHaveDifferentSerials(t *testing.T) {
	b, _ := Generate(defaultOpts())
	ca := parsePEMCert(t, b.CACert)
	cl := parsePEMCert(t, b.ClientCert)
	if ca.SerialNumber.Cmp(cl.SerialNumber) == 0 {
		t.Error("CA and client serial numbers should differ")
	}
}

func TestSelfSigned_ECDSA_TwoRunsProduceUniqueSerials(t *testing.T) {
	b1, _ := Generate(defaultOpts())
	b2, _ := Generate(defaultOpts())
	s1 := parsePEMCert(t, b1.CACert).SerialNumber
	s2 := parsePEMCert(t, b2.CACert).SerialNumber
	if s1.Cmp(s2) == 0 {
		t.Error("two independent CA serials should differ")
	}
}

func TestSelfSigned_ECDSA_TwoRunsProduceDifferentKeys(t *testing.T) {
	b1, _ := Generate(defaultOpts())
	b2, _ := Generate(defaultOpts())
	if b1.CACert == b2.CACert {
		t.Error("two independent CA certs should differ")
	}
	if b1.CAKey == b2.CAKey {
		t.Error("two independent CA keys should differ")
	}
}

// ─── self-signed RSA ──────────────────────────────────────────────────────────

func TestSelfSigned_RSA_2048_BothKeys(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo, o.ClientAlgo = AlgoRSA, AlgoRSA
	o.CARSABits, o.ClientRSABits = 2048, 2048
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRSABits(t, "ca", b.CAKey, 2048)
	assertRSABits(t, "client", b.ClientKey, 2048)
}

func TestSelfSigned_RSA_4096_BothKeys(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo, o.ClientAlgo = AlgoRSA, AlgoRSA
	o.CARSABits, o.ClientRSABits = 4096, 4096
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRSABits(t, "ca", b.CAKey, 4096)
	assertRSABits(t, "client", b.ClientKey, 4096)
}

func TestSelfSigned_RSA_3072_CA(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo = AlgoRSA
	o.CARSABits = 3072
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRSABits(t, "ca", b.CAKey, 3072)
}

func TestSelfSigned_RSA_ClientSignedByCA(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo, o.ClientAlgo = AlgoRSA, AlgoRSA
	o.CARSABits, o.ClientRSABits = 2048, 2048
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	verifyClientAgainstCA(t, b.CACert, b.ClientCert)
}

// ─── mixed algorithms ─────────────────────────────────────────────────────────

func TestMixed_ECDSACAandRSAClient(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo, o.ClientAlgo = AlgoECDSA, AlgoRSA
	o.ClientRSABits = 2048
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := parsePEMKey(t, b.CAKey).(*ecdsa.PrivateKey); !ok {
		t.Error("CA key should be ECDSA")
	}
	if _, ok := parsePEMKey(t, b.ClientKey).(*rsa.PrivateKey); !ok {
		t.Error("client key should be RSA")
	}
	verifyClientAgainstCA(t, b.CACert, b.ClientCert)
}

func TestMixed_RSACAandECDSAClient(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo, o.ClientAlgo = AlgoRSA, AlgoECDSA
	o.CARSABits = 2048
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := parsePEMKey(t, b.CAKey).(*rsa.PrivateKey); !ok {
		t.Error("CA key should be RSA")
	}
	if _, ok := parsePEMKey(t, b.ClientKey).(*ecdsa.PrivateKey); !ok {
		t.Error("client key should be ECDSA")
	}
	verifyClientAgainstCA(t, b.CACert, b.ClientCert)
}

// ─── CA-signed mode ───────────────────────────────────────────────────────────

func TestCASigned_ECDSA_CA_ECDSAClient_AllFieldsPopulated(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNonEmpty(t, "ca_cert", b.CACert)
	assertNonEmpty(t, "ca_key", b.CAKey)
	assertNonEmpty(t, "client_cert", b.ClientCert)
	assertNonEmpty(t, "client_key", b.ClientKey)
}

func TestCASigned_BundleReturnsProvidedCACert(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, _ := Generate(o)
	if b.CACert != caCertPEM {
		t.Error("bundle CACert should equal provided CA cert")
	}
	if b.CAKey != caKeyPEM {
		t.Error("bundle CAKey should equal provided CA key")
	}
}

func TestCASigned_ECDSA_CA_ECDSAClient_Verifies(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	verifyClientAgainstCA(t, caCertPEM, b.ClientCert)
}

func TestCASigned_ECDSA_CA_RSAClient_Verifies(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ClientAlgo, o.ClientRSABits = AlgoRSA, 2048
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := parsePEMKey(t, b.ClientKey).(*rsa.PrivateKey); !ok {
		t.Error("client key should be RSA")
	}
	verifyClientAgainstCA(t, caCertPEM, b.ClientCert)
}

func TestCASigned_RSA_CA_ECDSAClient_Verifies(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoRSA, 2048)
	o := defaultOpts()
	o.ClientAlgo = AlgoECDSA
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	verifyClientAgainstCA(t, caCertPEM, b.ClientCert)
}

func TestCASigned_RSA_CA_RSAClient_Verifies(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoRSA, 2048)
	o := defaultOpts()
	o.ClientAlgo, o.ClientRSABits = AlgoRSA, 2048
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	verifyClientAgainstCA(t, caCertPEM, b.ClientCert)
}

func TestCASigned_ClientIsNotCA(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, _ := Generate(o)
	if parsePEMCert(t, b.ClientCert).IsCA {
		t.Error("CA-signed client cert should not be a CA")
	}
}

func TestCASigned_ClientCommonNamePropagated(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.CommonName = "tenant-xyz-999"
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, _ := Generate(o)
	if got := parsePEMCert(t, b.ClientCert).Subject.CommonName; got != o.CommonName {
		t.Errorf("client CN: want %q, got %q", o.CommonName, got)
	}
}

func TestCASigned_ClientValidityRespectsDays(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.Days = 90
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, _ := Generate(o)
	cert := parsePEMCert(t, b.ClientCert)
	expected := time.Duration(o.Days) * 24 * time.Hour
	got := cert.NotAfter.Sub(cert.NotBefore)
	if diff := got - expected; diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("client validity: want ~%v, got %v", expected, got)
	}
}

func TestCASigned_MultipleClientCertsHaveUniqueSerials(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b1, _ := Generate(o)
	b2, _ := Generate(o)
	s1 := parsePEMCert(t, b1.ClientCert).SerialNumber
	s2 := parsePEMCert(t, b2.ClientCert).SerialNumber
	if s1.Cmp(s2) == 0 {
		t.Error("two client serials from same CA should differ")
	}
}

func TestCASigned_ClientHasClientAuthEKU(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
	b, _ := Generate(o)
	cert := parsePEMCert(t, b.ClientCert)
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return
		}
	}
	t.Error("CA-signed client cert: missing ExtKeyUsageClientAuth")
}

// ─── error cases ──────────────────────────────────────────────────────────────

func TestError_EmptyCommonName(t *testing.T) {
	o := defaultOpts()
	o.CommonName = ""
	if _, err := Generate(o); err == nil {
		t.Error("expected error for empty common_name")
	}
}

func TestError_ZeroDays(t *testing.T) {
	o := defaultOpts()
	o.Days = 0
	if _, err := Generate(o); err == nil {
		t.Error("expected error for days=0")
	}
}

func TestError_NegativeDays(t *testing.T) {
	o := defaultOpts()
	o.Days = -100
	if _, err := Generate(o); err == nil {
		t.Error("expected error for negative days")
	}
}

func TestError_RSABitsBelowMinimum_CA(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo = AlgoRSA
	o.CARSABits = 1024
	if _, err := Generate(o); err == nil {
		t.Error("expected error for CA rsa_bits < 2048")
	}
}

func TestError_RSABitsBelowMinimum_Client(t *testing.T) {
	o := defaultOpts()
	o.ClientAlgo = AlgoRSA
	o.ClientRSABits = 512
	if _, err := Generate(o); err == nil {
		t.Error("expected error for client rsa_bits < 2048")
	}
}

func TestError_UnknownCAAlgorithm(t *testing.T) {
	o := defaultOpts()
	o.CAAlgo = 99
	if _, err := Generate(o); err == nil {
		t.Error("expected error for unknown CA algorithm")
	}
}

func TestError_UnknownClientAlgorithm(t *testing.T) {
	o := defaultOpts()
	o.ClientAlgo = 99
	if _, err := Generate(o); err == nil {
		t.Error("expected error for unknown client algorithm")
	}
}

func TestError_InvalidCACertPEM(t *testing.T) {
	o := defaultOpts()
	o.ProvidedCACert = "not-pem"
	o.ProvidedCAKey = "not-pem"
	if _, err := Generate(o); err == nil {
		t.Error("expected error for invalid CA cert PEM")
	}
}

func TestError_ValidPEMWrongType(t *testing.T) {
	// A valid PEM block but it's a key, not a cert.
	o := defaultOpts()
	o.ProvidedCACert = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----"
	o.ProvidedCAKey = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----"
	if _, err := Generate(o); err == nil {
		t.Error("expected error when PEM contains a key where a cert is expected")
	}
}

func TestError_NonCACertUsedAsCA(t *testing.T) {
	b, _ := Generate(defaultOpts())
	o := defaultOpts()
	o.ProvidedCACert = b.ClientCert // not a CA cert
	o.ProvidedCAKey = b.ClientKey
	if _, err := Generate(o); err == nil {
		t.Error("expected error when non-CA cert is used as CA")
	}
}

func TestError_MismatchedCAKeyAndCert(t *testing.T) {
	b1, _ := Generate(defaultOpts())
	b2, _ := Generate(defaultOpts())
	o := defaultOpts()
	o.ProvidedCACert = b1.CACert
	o.ProvidedCAKey = b2.CAKey // from a different CA
	if _, err := Generate(o); err == nil {
		t.Error("expected error for mismatched CA cert and key")
	}
}

func TestError_CorruptedCAKeyData(t *testing.T) {
	caCertPEM, _ := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert = caCertPEM
	// Syntactically valid PEM but the base64 is garbage.
	o.ProvidedCAKey = "-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2hp\n-----END PRIVATE KEY-----"
	if _, err := Generate(o); err == nil {
		t.Error("expected error for corrupted CA key bytes")
	}
}

func TestError_OnlyCACertProvided_FallsBackToSelfSigned(t *testing.T) {
	// When only one of the two CA fields is set, we fall back to self-signed.
	// This is by design: both must be non-empty to enter CA-signed mode.
	_, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	o := defaultOpts()
	o.ProvidedCACert = ""    // empty
	o.ProvidedCAKey = caKeyPEM // non-empty — but ignored
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("expected self-signed fallback, got error: %v", err)
	}
	assertNonEmpty(t, "ca_cert", b.CACert)
}

// ─── stress / edge cases ─────────────────────────────────────────────────────

func TestStress_TenConsecutiveBundlesHaveUniqueCASerials(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		b, err := Generate(defaultOpts())
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		s := parsePEMCert(t, b.CACert).SerialNumber.String()
		if seen[s] {
			t.Errorf("iteration %d: duplicate CA serial %s", i, s)
		}
		seen[s] = true
	}
}

func TestStress_ThirtyYearValidity(t *testing.T) {
	o := defaultOpts()
	o.Days = 365 * 30
	if _, err := Generate(o); err != nil {
		t.Errorf("unexpected error for 30-year validity: %v", err)
	}
}

func TestStress_OneDayValidity(t *testing.T) {
	o := defaultOpts()
	o.Days = 1
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error for 1-day validity: %v", err)
	}
	verifyClientAgainstCA(t, b.CACert, b.ClientCert)
}

func TestStress_MaxLengthCommonName(t *testing.T) {
	o := defaultOpts()
	o.CommonName = strings.Repeat("x", 64)
	if _, err := Generate(o); err != nil {
		t.Errorf("unexpected error for 64-char CN: %v", err)
	}
}

func TestStress_SpecialCharsInCommonName(t *testing.T) {
	o := defaultOpts()
	o.CommonName = "tenant-123.example.com"
	b, err := Generate(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := parsePEMCert(t, b.CACert).Subject.CommonName; got != o.CommonName {
		t.Errorf("CN: want %q, got %q", o.CommonName, got)
	}
}

func TestStress_FiftyCASignedCertsFromSameCA_AllVerify(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	serials := make(map[string]bool)
	for i := 0; i < 50; i++ {
		o := defaultOpts()
		o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
		b, err := Generate(o)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		verifyClientAgainstCA(t, caCertPEM, b.ClientCert)
		s := parsePEMCert(t, b.ClientCert).SerialNumber.String()
		if serials[s] {
			t.Errorf("iteration %d: duplicate client serial", i)
		}
		serials[s] = true
	}
}

func TestStress_ConcurrentSelfSignedGeneration(t *testing.T) {
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, err := Generate(defaultOpts())
			results <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-results; err != nil {
			t.Errorf("concurrent generation error: %v", err)
		}
	}
}

func TestStress_ConcurrentCASignedGeneration(t *testing.T) {
	caCertPEM, caKeyPEM := externalCA(t, AlgoECDSA, 0)
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			o := defaultOpts()
			o.ProvidedCACert, o.ProvidedCAKey = caCertPEM, caKeyPEM
			_, err := Generate(o)
			results <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-results; err != nil {
			t.Errorf("concurrent CA-signed generation error: %v", err)
		}
	}
}
