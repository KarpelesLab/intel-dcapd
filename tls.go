package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

var (
	// In-memory certificate cache
	certMutex     sync.RWMutex
	cachedCert    *tls.Certificate
	certExpiresAt time.Time
)

// getOrGenerateCert returns a TLS certificate, either from files or generated in-memory
func getOrGenerateCert() (tls.Certificate, error) {
	certFile := os.Getenv("DCAPD_CERT_FILE")
	keyFile := os.Getenv("DCAPD_KEY_FILE")

	// If both cert and key files are specified, load from disk
	if certFile != "" && keyFile != "" {
		log.Printf("Loading TLS certificate from %s and %s", certFile, keyFile)
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	// Otherwise, use in-memory certificate
	return getInMemoryCert()
}

// getInMemoryCert returns an in-memory TLS certificate, generating if needed
func getInMemoryCert() (tls.Certificate, error) {
	certMutex.RLock()
	// Check if we have a valid cached certificate
	if cachedCert != nil && time.Now().Before(certExpiresAt) {
		cert := *cachedCert
		certMutex.RUnlock()
		return cert, nil
	}
	certMutex.RUnlock()

	// Need to generate new certificate
	certMutex.Lock()
	defer certMutex.Unlock()

	// Double-check after acquiring write lock
	if cachedCert != nil && time.Now().Before(certExpiresAt) {
		return *cachedCert, nil
	}

	log.Println("Generating new self-signed TLS certificate (in-memory)")
	cert, expiresAt, err := generateSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, err
	}

	cachedCert = &cert
	certExpiresAt = expiresAt
	log.Printf("Generated self-signed certificate (valid until %s)", expiresAt.Format(time.RFC3339))

	return cert, nil
}

// generateSelfSignedCert creates a new self-signed TLS certificate in memory
func generateSelfSignedCert() (tls.Certificate, time.Time, error) {
	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Intel DCAP Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	// Encode private key to PKCS8 DER format
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	// Create PEM blocks
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	// Parse into tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	return tlsCert, notAfter, nil
}
