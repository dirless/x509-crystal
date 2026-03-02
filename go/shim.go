package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef struct {
	char *ca_cert;
	char *ca_key;
	char *client_cert;
	char *client_key;
	char *error;
	int   status; // 0 = success, 1 = error
} X509Result;
*/
import "C"
import "unsafe"

//export x509_generate
//
// Generates a CA certificate and a client certificate signed by that CA.
//
// Parameters:
//   cn              - common name applied to both certificates
//   days            - validity period in days; in CA-signed mode applies only
//                     to the client cert (the provided CA's validity is fixed)
//   ca_algo         - CA key algorithm:     0 = ECDSA P-256, 1 = RSA
//   client_algo     - client key algorithm: 0 = ECDSA P-256, 1 = RSA
//   ca_rsa_bits     - RSA bit size for CA key     (ignored when ca_algo = 0)
//   client_rsa_bits - RSA bit size for client key (ignored when client_algo = 0)
//   provided_ca_cert - PEM of an existing CA certificate, or NULL for self-signed
//   provided_ca_key  - PEM of the matching CA private key, or NULL for self-signed
//
// Returns a heap-allocated X509Result. Caller MUST call x509_free() when done.
// On error, status = 1 and the error field contains a message; all cert fields are NULL.
// On success, status = 0 and all four cert/key fields are populated.
func x509_generate(
	cn *C.char,
	days C.int,
	ca_algo C.int,
	client_algo C.int,
	ca_rsa_bits C.int,
	client_rsa_bits C.int,
	provided_ca_cert *C.char,
	provided_ca_key *C.char,
) *C.X509Result {
	result := (*C.X509Result)(C.calloc(1, C.sizeof_X509Result))

	opts := GenerateOptions{
		CommonName:    C.GoString(cn),
		Days:          int(days),
		CAAlgo:        int(ca_algo),
		ClientAlgo:    int(client_algo),
		CARSABits:     int(ca_rsa_bits),
		ClientRSABits: int(client_rsa_bits),
	}
	// Only set provided CA fields when both pointers are non-NULL.
	if provided_ca_cert != nil && provided_ca_key != nil {
		opts.ProvidedCACert = C.GoString(provided_ca_cert)
		opts.ProvidedCAKey = C.GoString(provided_ca_key)
	}

	bundle, err := Generate(opts)
	if err != nil {
		result.status = 1
		result.error = C.CString(err.Error())
		return result
	}

	result.status = 0
	result.ca_cert = C.CString(bundle.CACert)
	result.ca_key = C.CString(bundle.CAKey)
	result.client_cert = C.CString(bundle.ClientCert)
	result.client_key = C.CString(bundle.ClientKey)
	return result
}

//export x509_free
//
// Releases all memory allocated by x509_generate.
// Must be called exactly once per result returned by x509_generate.
// Safe to call with a NULL pointer.
func x509_free(result *C.X509Result) {
	if result == nil {
		return
	}
	if result.ca_cert != nil {
		C.free(unsafe.Pointer(result.ca_cert))
	}
	if result.ca_key != nil {
		C.free(unsafe.Pointer(result.ca_key))
	}
	if result.client_cert != nil {
		C.free(unsafe.Pointer(result.client_cert))
	}
	if result.client_key != nil {
		C.free(unsafe.Pointer(result.client_key))
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
	}
	C.free(unsafe.Pointer(result))
}

// main is required for buildmode=c-shared but is never called at runtime.
func main() {}
