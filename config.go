package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
)

// Config holds runtime configuration.
type Config struct {
	Alias         string
	Port          int
	MulticastAddr string
	DownloadDir   string
	Protocol      string
	DeviceType    string
	DeviceModel   string
	Fingerprint   string
	TLSCert       tls.Certificate
	CertDER       []byte
	Logger        *Logger
	BindIP        string
	BindIface     *net.Interface
}

func defaultDownloadDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./downloads"
	}
	return filepath.Join(home, "Downloads")
}
