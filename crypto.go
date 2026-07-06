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
	"time"
)

// generateSelfSignedCert creates a self-signed ECDSA certificate.
// It returns the TLS certificate, raw DER bytes, and SHA-256 fingerprint (hex).
func generateSelfSignedCert(bindIP string) (tls.Certificate, []byte, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LocalSend CLI"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
		return tls.Certificate{}, nil, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}

	fingerprint := sha256.Sum256(certDER)
	return tlsCert, certDER, hex.EncodeToString(fingerprint[:]), nil
}
