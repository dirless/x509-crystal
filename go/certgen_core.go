package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Algorithm constants — must stay in sync with the Crystal Algorithm enum.
const (
	AlgoECDSA = 0
	AlgoRSA   = 1
)

// CertBundle holds the four PEM strings returned to callers.
type CertBundle struct {
	CACert     string
	CAKey      string
	ClientCert string
	ClientKey  string
}

// GenerateOptions controls certificate generation.
type GenerateOptions struct {
	CommonName    string
	Days          int
	CAAlgo        int
	ClientAlgo    int
	CARSABits     int
	ClientRSABits int
	// CA-signed mode: when both are non-empty the provided CA is used.
	ProvidedCACert string
	ProvidedCAKey  string
}

// Generate is the single entry point for all certificate generation.
// It is pure Go and has no CGo dependencies, making it fully unit-testable.
func Generate(o GenerateOptions) (*CertBundle, error) {
	if o.CommonName == "" {
		return nil, fmt.Errorf("common_name must not be empty")
	}
	if o.Days <= 0 {
		return nil, fmt.Errorf("days must be positive, got %d", o.Days)
	}

	// Generate the client key first (always fresh regardless of mode).
	clientKey, err := genKey(o.ClientAlgo, o.ClientRSABits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %w", err)
	}
	clientKeyPEM, err := marshalPrivKey(clientKey)
	if err != nil {
		return nil, err
	}

	var caCertPEM, caKeyPEM string
	var caCert *x509.Certificate
	var caKey any

	caProvided := o.ProvidedCACert != "" && o.ProvidedCAKey != ""

	if caProvided {
		caCert, caKey, err = parseCA(o.ProvidedCACert, o.ProvidedCAKey)
		if err != nil {
			return nil, err
		}
		caCertPEM = o.ProvidedCACert
		caKeyPEM = o.ProvidedCAKey
	} else {
		freshCAKey, err := genKey(o.CAAlgo, o.CARSABits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA key: %w", err)
		}
		rawCAKeyPEM, err := marshalPrivKey(freshCAKey)
		if err != nil {
			return nil, err
		}
		caKeyPEM = string(rawCAKeyPEM)

		rawCACertPEM, parsedCACert, err := createCACert(o.CommonName, o.Days, freshCAKey)
		if err != nil {
			return nil, err
		}
		caCertPEM = string(rawCACertPEM)
		caCert = parsedCACert
		caKey = freshCAKey
	}

	clientCertPEM, err := createClientCert(o.CommonName, o.Days, clientKey, caCert, caKey)
	if err != nil {
		return nil, err
	}

	return &CertBundle{
		CACert:     caCertPEM,
		CAKey:      caKeyPEM,
		ClientCert: string(clientCertPEM),
		ClientKey:  string(clientKeyPEM),
	}, nil
}

// genKey generates a private key for the requested algorithm.
func genKey(algo, rsaBits int) (any, error) {
	switch algo {
	case AlgoECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgoRSA:
		if rsaBits < 2048 {
			return nil, fmt.Errorf("rsa_bits must be at least 2048, got %d", rsaBits)
		}
		return rsa.GenerateKey(rand.Reader, rsaBits)
	default:
		return nil, fmt.Errorf("unknown algorithm constant: %d", algo)
	}
}

// pubKey extracts the public half of a private key.
func pubKey(priv any) any {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *rsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

// marshalPrivKey encodes any supported private key as PKCS8 PEM.
func marshalPrivKey(priv any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// randomSerial returns a random 128-bit serial number (RFC 5280 §4.1.2.2).
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// notBefore returns now minus one minute to tolerate minor clock skew.
func notBefore() time.Time {
	return time.Now().Add(-1 * time.Minute)
}

// createCACert builds and signs a self-signed CA certificate.
// Returns the PEM bytes and the parsed *x509.Certificate for immediate use.
func createCACert(cn string, days int, caKey any) ([]byte, *x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA serial: %w", err)
	}

	nb := notBefore()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"x509-crystal"},
		},
		NotBefore:             nb,
		NotAfter:              nb.Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	// template == parent → self-signed.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey(caKey), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Parse back so we can use it as parent when signing the client cert.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-parse CA certificate: %w", err)
	}

	return certPEM, parsed, nil
}

// createClientCert builds a client certificate signed by the given CA.
func createClientCert(cn string, days int, clientKey any, caCert *x509.Certificate, caKey any) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client serial: %w", err)
	}

	nb := notBefore()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"x509-crystal"},
		},
		NotBefore:             nb,
		NotAfter:              nb.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey(clientKey), caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// parseCA parses a PEM CA certificate and its corresponding private key.
// Accepts PKCS8, legacy EC, and legacy RSA private key formats.
func parseCA(certPEM, keyPEM string) (*x509.Certificate, any, error) {
	// Decode certificate.
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM block")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("provided certificate is not a CA (IsCA=false)")
	}

	// Decode private key.
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM block")
	}

	var caKey any
	switch keyBlock.Type {
	case "PRIVATE KEY": // PKCS8 — our preferred format
		caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		var rsaKey *rsa.PrivateKey
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		caKey = rsaKey
	default:
		return nil, nil, fmt.Errorf("unsupported private key PEM type: %q", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Verify the key actually matches the certificate's public key by attempting
	// to sign a throwaway certificate — this surfaces mismatches early.
	if err := verifyKeyMatchesCert(caCert, caKey); err != nil {
		return nil, nil, fmt.Errorf("CA key does not match CA certificate: %w", err)
	}

	return caCert, caKey, nil
}

// verifyKeyMatchesCert signs a throwaway cert to confirm the key matches.
func verifyKeyMatchesCert(caCert *x509.Certificate, caKey any) error {
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "key-check"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute),
	}
	_, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey(caKey), caKey)
	return err
}
