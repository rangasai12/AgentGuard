package network

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestGenerateCAIsSelfSignedAndIsCA(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !ca.cert.IsCA {
		t.Error("expected generated certificate to be a CA")
	}
	if err := ca.cert.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("expected CA cert to be self-signed: %v", err)
	}
}

func TestLeafForIsSignedByCAAndMatchesHost(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	leaf, err := ca.LeafFor("api.example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}
	if err := leafCert.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("expected leaf cert to be signed by the CA: %v", err)
	}
	if len(leafCert.DNSNames) != 1 || leafCert.DNSNames[0] != "api.example.com" {
		t.Errorf("expected DNSNames [api.example.com], got %v", leafCert.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: pool}); err != nil {
		t.Errorf("leaf certificate did not verify against the CA pool: %v", err)
	}
}

func TestLeafForIPLiteral(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leaf, err := ca.LeafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}
	if len(leafCert.IPAddresses) != 1 || leafCert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("expected IPAddresses [127.0.0.1], got %v", leafCert.IPAddresses)
	}
}

func TestLeafForIsCached(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	a, err := ca.LeafFor("cached.example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	b, err := ca.LeafFor("cached.example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Error("expected LeafFor to return a cached certificate on the second call for the same host")
	}
}

func TestSaveAndLoadCARoundTrips(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	original, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := original.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if loaded.cert.SerialNumber.Cmp(original.cert.SerialNumber) != 0 {
		t.Error("loaded CA has a different serial number than the original")
	}

	// The loaded CA's key must actually be able to sign leaves that verify
	// against the loaded cert — proves the key round-tripped correctly, not
	// just the certificate.
	leaf, err := loaded.LeafFor("round-trip.example.com")
	if err != nil {
		t.Fatalf("LeafFor after reload: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}
	if err := leafCert.CheckSignatureFrom(loaded.cert); err != nil {
		t.Errorf("leaf signed after reload does not verify against the reloaded CA: %v", err)
	}
}

func TestLoadOrGenerateCACreatesThenReuses(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	first, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (create): %v", err)
	}
	second, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (reuse): %v", err)
	}
	if first.cert.SerialNumber.Cmp(second.cert.SerialNumber) != 0 {
		t.Error("expected LoadOrGenerateCA to reuse the saved CA on the second call, got a different one")
	}
}

// tlsConfigTrusting builds a client-side tls.Config that trusts ca, for
// tests that dial through the proxy's MITM'd TLS layer.
func tlsConfigTrusting(ca *CA) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &tls.Config{RootCAs: pool}
}
