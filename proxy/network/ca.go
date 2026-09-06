package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CA is a certificate authority used to mint short-lived leaf certificates
// on the fly for TLS interception, and caches issued leaf certificates per
// host so a live connection doesn't pay certificate-generation cost more
// than once. It never persists leaf certificates — only the CA itself is
// meant to be saved and trusted once.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// GenerateCA creates a new self-signed CA, not tied to any file. Callers
// that want it to persist across proxy restarts use Save/LoadCA.
func GenerateCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"AgentGuard local interception CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}
	return &CA{cert: cert, key: key, cache: make(map[string]*tls.Certificate)}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial: %w", err)
	}
	return n, nil
}

// CertPEM returns the CA certificate in PEM form — this is what a user
// trusts (via SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, --cacert, or their OS/
// browser trust store) to make TLS interception work without certificate
// errors on the client side.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

func (ca *CA) keyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("encoding CA private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Save writes the CA certificate (mode 0644) and private key (mode 0600) to
// certPath/keyPath.
func (ca *CA) Save(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, ca.CertPEM(), 0o644); err != nil {
		return fmt.Errorf("writing CA cert to %s: %w", certPath, err)
	}
	keyPEM, err := ca.keyPEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("writing CA key to %s: %w", keyPath, err)
	}
	return nil
}

// LoadCA reads a previously-saved CA from disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEMBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert %s: %w", certPath, err)
	}
	keyPEMBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEMBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM certificate block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEMBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM key block found in %s", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key %s: %w", keyPath, err)
	}

	return &CA{cert: cert, key: key, cache: make(map[string]*tls.Certificate)}, nil
}

// LoadOrGenerateCA loads a CA from certPath/keyPath, generating and saving a
// new one (creating parent directories as needed) if either file is missing.
func LoadOrGenerateCA(certPath, keyPath string) (*CA, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		return LoadCA(certPath, keyPath)
	}

	ca, err := GenerateCA("AgentGuard Local Interception CA")
	if err != nil {
		return nil, err
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		return nil, err
	}
	return ca, nil
}

// LeafFor returns a certificate for host, signed by ca, generating and
// caching it on first use. host may be a DNS name or an IP literal.
func (ca *CA) LeafFor(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key for %s: %w", host, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate for %s: %w", host, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
	}
	ca.cache[host] = tlsCert
	return tlsCert, nil
}
