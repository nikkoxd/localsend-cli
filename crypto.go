package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// loadOrCreateCert returns the stored certificate, generating and storing one
// on first use. Peers identify us by its fingerprint, so a certificate that
// changed every run would show up as a new device each time and could never be
// marked as known. Falls back to an in-memory certificate if the store is
// unusable.
func loadOrCreateCert(bindIP string, logger *Logger) (tls.Certificate, []byte, string, error) {
	dir, err := certDir()
	if err != nil {
		logger.Debugf("No certificate directory (%v), generating a temporary certificate\n", err)
		return generateSelfSignedCert(bindIP)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil && len(cert.Certificate) > 0 {
		logger.Debugf("Loaded certificate from %s\n", certPath)
		fingerprint := sha256.Sum256(cert.Certificate[0])
		return cert, cert.Certificate[0], hex.EncodeToString(fingerprint[:]), nil
	}
	if !os.IsNotExist(err) && err != nil {
		logger.Debugf("Stored certificate unusable (%v), generating a new one\n", err)
	}

	certPEM, keyPEM, err := generateSelfSignedCertPEM(bindIP)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		logger.Debugf("Could not store certificate: %v\n", err)
	} else if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		logger.Debugf("Could not store private key: %v\n", err)
		os.Remove(certPath)
	} else {
		logger.Debugf("Stored new certificate in %s\n", dir)
	}
	return certFromPEM(certPEM, keyPEM)
}

// certDir is where the certificate lives, under XDG_DATA_HOME rather than the
// cache directory: it is an identity, and losing it renames us to every peer.
func certDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "localsend-cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// generateSelfSignedCert creates a self-signed ECDSA certificate.
// It returns the TLS certificate, raw DER bytes, and SHA-256 fingerprint (hex).
func generateSelfSignedCert(bindIP string) (tls.Certificate, []byte, string, error) {
	certPEM, keyPEM, err := generateSelfSignedCertPEM(bindIP)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	return certFromPEM(certPEM, keyPEM)
}

func certFromPEM(certPEM, keyPEM []byte) (tls.Certificate, []byte, string, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	fingerprint := sha256.Sum256(cert.Certificate[0])
	return cert, cert.Certificate[0], hex.EncodeToString(fingerprint[:]), nil
}

func generateSelfSignedCertPEM(bindIP string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LocalSend CLI"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	if bindIP != "" {
		if ip := net.ParseIP(bindIP); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	} else {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					template.IPAddresses = append(template.IPAddresses, ip4)
				} else if ipnet.IP.To16() != nil {
					template.IPAddresses = append(template.IPAddresses, ipnet.IP)
				}
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}
