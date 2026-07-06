package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	protocolVersion      = "2.1"
	defaultMulticastAddr = "224.0.0.167:53317"
	defaultPort          = 53317
	defaultDeviceType    = "desktop"
)

var defaultAlias = func() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "LocalSend CLI"
}()

// DeviceInfo represents the device announcement and registration payload.
type DeviceInfo struct {
	Alias       string `json:"alias"`
	Version     string `json:"version"`
	DeviceModel string `json:"deviceModel,omitempty"`
	DeviceType  string `json:"deviceType"`
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Download    bool   `json:"download,omitempty"`
	Announce    bool   `json:"announce,omitempty"`
}

// FileMetadata describes a file to be transferred.
type FileMetadata struct {
	ID       string `json:"id"`
	FileName string `json:"fileName"`
	Size     int64  `json:"size"`
	FileType string `json:"fileType,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Preview  string `json:"preview,omitempty"`
	Metadata *struct {
		Modified string `json:"modified,omitempty"`
		Accessed string `json:"accessed,omitempty"`
	} `json:"metadata,omitempty"`
}

// PrepareUploadRequest is sent by the sender to the receiver.
type PrepareUploadRequest struct {
	Info  DeviceInfo              `json:"info"`
	Files map[string]FileMetadata `json:"files"`
}

// PrepareUploadResponse is returned by the receiver.
type PrepareUploadResponse struct {
	SessionID string            `json:"sessionId"`
	Files     map[string]string `json:"files"` // fileId -> token
}

// DiscoveredDevice holds info about a found peer.
type DiscoveredDevice struct {
	Info DeviceInfo `json:"info"`
	IP   string     `json:"ip"`
	Port int        `json:"port"`
}

// ReceiveSession tracks an active incoming transfer.
type ReceiveSession struct {
	SessionID string
	Files     map[string]FileMetadata
	Tokens    map[string]string
}

// String returns a human-readable summary.
func (d DiscoveredDevice) String() string {
	return fmt.Sprintf("%s (%s) at %s:%d", d.Info.Alias, d.Info.DeviceType, d.IP, d.Port)
}

// JSON returns the JSON encoding of the device info.
func (d DiscoveredDevice) JSON() ([]byte, error) {
	return json.Marshal(d)
}

