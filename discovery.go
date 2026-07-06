package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// discover performs UDP multicast discovery only.
func discover(cfg *Config, timeout time.Duration) []DiscoveredDevice {
	var mu sync.Mutex
	found := make(map[string]DiscoveredDevice)
	var wg sync.WaitGroup

	wg.Go(func() {
		discoverMulticast(cfg, timeout, &mu, found)
	})

	wg.Wait()

	var results []DiscoveredDevice
	for _, d := range found {
		results = append(results, d)
	}
	return results
}

// sendMulticastAnnouncement sends a single UDP multicast announcement
// without listening for responses. Returns error if sending fails.
func sendMulticastAnnouncement(cfg *Config) error {
	addr, err := net.ResolveUDPAddr("udp", cfg.MulticastAddr)
	if err != nil {
		return fmt.Errorf("resolve multicast address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial multicast: %w", err)
	}
	defer conn.Close()

	announcement := DeviceInfo{
		Alias:       cfg.Alias,
		Version:     protocolVersion,
		DeviceType:  cfg.DeviceType,
		DeviceModel: cfg.DeviceModel,
		Fingerprint: cfg.Fingerprint,
		Port:        cfg.Port,
		Protocol:    cfg.Protocol,
		Download:    false,
		Announce:    true,
	}
	data, err := json.Marshal(announcement)
	if err != nil {
		return fmt.Errorf("marshal announcement: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write announcement: %w", err)
	}
	return nil
}

// announceLoop periodically sends multicast announcements until the context is done.
func announceLoop(cfg *Config, interval time.Duration, stop <-chan struct{}) {
	// Send immediately on startup
	if err := sendMulticastAnnouncement(cfg); err != nil {
		cfg.Logger.Debugf("Announcement failed: %v\n", err)
	} else {
		cfg.Logger.Debugf("Sent multicast announcement\n")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sendMulticastAnnouncement(cfg); err != nil {
				cfg.Logger.Debugf("Announcement failed: %v\n", err)
			} else {
				cfg.Logger.Debugf("Sent multicast announcement\n")
			}
		case <-stop:
			cfg.Logger.Debugf("Announcement loop stopped\n")
			return
		}
	}
}

func discoverMulticast(cfg *Config, timeout time.Duration, mu *sync.Mutex, found map[string]DiscoveredDevice) {
	addr, err := net.ResolveUDPAddr("udp", cfg.MulticastAddr)
	if err != nil {
		cfg.Logger.Debugf("Multicast resolve failed: %v\n", err)
		return
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		cfg.Logger.Debugf("Multicast listen failed: %v\n", err)
		return
	}
	defer conn.Close()

	cfg.Logger.Debugf("Multicast listening on %s\n", cfg.MulticastAddr)

	// Send announcement
	announcement := DeviceInfo{
		Alias:       cfg.Alias,
		Version:     protocolVersion,
		DeviceType:  cfg.DeviceType,
		DeviceModel: cfg.DeviceModel,
		Fingerprint: cfg.Fingerprint,
		Port:        cfg.Port,
		Protocol:    cfg.Protocol,
		Download:    false,
		Announce:    true,
	}
	data, _ := json.Marshal(announcement)
	if _, err := conn.WriteToUDP(data, addr); err != nil {
		cfg.Logger.Debugf("Multicast announcement failed: %v\n", err)
	} else {
		cfg.Logger.Debugf("Sent multicast announcement\n")
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				cfg.Logger.Debugf("Multicast discovery timed out\n")
				break
			}
			cfg.Logger.Debugf("Multicast read error: %v\n", err)
			continue
		}
		var info DeviceInfo
		if err := json.Unmarshal(buf[:n], &info); err != nil {
			cfg.Logger.Debugf("Multicast parse error from %s: %v\n", src, err)
			continue
		}
		if info.Fingerprint == cfg.Fingerprint {
			continue
		}
		cfg.Logger.Debugf("Multicast response from %s: alias=%s port=%d\n", src.IP, info.Alias, info.Port)
		if info.Announce {
			go registerDevice(cfg, src.IP.String(), info.Port, mu, found)
		} else {
			mu.Lock()
			key := fmt.Sprintf("%s:%d", src.IP.String(), info.Port)
			if _, ok := found[key]; !ok {
				found[key] = DiscoveredDevice{Info: info, IP: src.IP.String(), Port: info.Port}
				cfg.Logger.Infof("Discovered via multicast: %s at %s:%d\n", info.Alias, src.IP, info.Port)
			}
			mu.Unlock()
		}
	}
}

func registerDevice(cfg *Config, ip string, port int, mu *sync.Mutex, found map[string]DiscoveredDevice) {
	info := DeviceInfo{
		Alias:       cfg.Alias,
		Version:     protocolVersion,
		DeviceType:  cfg.DeviceType,
		DeviceModel: cfg.DeviceModel,
		Fingerprint: cfg.Fingerprint,
		Port:        cfg.Port,
		Protocol:    cfg.Protocol,
		Download:    false,
	}
	data, _ := json.Marshal(info)

	client := newHTTPClient()
	for _, proto := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s:%d/api/localsend/v2/register", proto, ip, port)
		cfg.Logger.Debugf("Registering to %s\n", url)
		resp, err := client.Post(url, "application/json", strings.NewReader(string(data)))
		if err != nil {
			cfg.Logger.Debugf("Register to %s failed: %v\n", url, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var peer DeviceInfo
			if err := json.Unmarshal(body, &peer); err != nil {
				cfg.Logger.Debugf("Register parse error from %s: %v\n", url, err)
				continue
			}
			// Populate missing fields from connection details
			if peer.Port == 0 {
				peer.Port = port
			}
			if peer.Protocol == "" {
				peer.Protocol = proto
			}
			mu.Lock()
			key := fmt.Sprintf("%s:%d", ip, port)
			if _, ok := found[key]; !ok {
				found[key] = DiscoveredDevice{Info: peer, IP: ip, Port: port}
				cfg.Logger.Infof("Discovered via HTTP: %s at %s:%d\n", peer.Alias, ip, port)
			}
			mu.Unlock()
			return
		}
		cfg.Logger.Debugf("Register to %s returned %d\n", url, resp.StatusCode)
	}
}

func newHTTPClient() *http.Client {
	return newHTTPClientWithTimeout(5 * time.Second)
}

func newHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// listenMulticastContinuous listens for UDP multicast packets indefinitely.
// When it receives an announcement (announce: true) from another device,
// it sends HTTP POST /register to that device to complete the two-way handshake.
// This should be run as a background goroutine during receive mode.
func listenMulticastContinuous(cfg *Config, stop <-chan struct{}) {
	addr, err := net.ResolveUDPAddr("udp", cfg.MulticastAddr)
	if err != nil {
		cfg.Logger.Debugf("Multicast listener resolve failed: %v\n", err)
		return
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		cfg.Logger.Debugf("Multicast listener bind failed: %v\n", err)
		return
	}
	defer conn.Close()

	cfg.Logger.Debugf("Multicast listener started on %s\n", cfg.MulticastAddr)

	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-stop:
					cfg.Logger.Debugf("Multicast listener stopped\n")
					return
				default:
					continue
				}
			}
			cfg.Logger.Debugf("Multicast listener read error: %v\n", err)
			select {
			case <-stop:
				cfg.Logger.Debugf("Multicast listener stopped\n")
				return
			default:
				continue
			}
		}

		var info DeviceInfo
		if err := json.Unmarshal(buf[:n], &info); err != nil {
			cfg.Logger.Debugf("Multicast listener parse error from %s: %v\n", src, err)
			continue
		}

		if info.Fingerprint == cfg.Fingerprint {
			continue // skip self
		}

		cfg.Logger.Debugf("Multicast listener: packet from %s alias=%s announce=%v\n", src.IP, info.Alias, info.Announce)

		if info.Announce {
			// Another device is announcing. Send HTTP POST /register to complete handshake.
			cfg.Logger.Debugf("Multicast listener: sending register to %s:%d\n", src.IP, info.Port)
			go func(ip string, port int) {
				var dummy sync.Mutex
				dummyFound := make(map[string]DiscoveredDevice)
				registerDevice(cfg, ip, port, &dummy, dummyFound)
			}(src.IP.String(), info.Port)
		} else {
			// This is a response to our announcement. Just log it.
			cfg.Logger.Debugf("Multicast listener: response from %s (%s)\n", src.IP, info.Alias)
		}
	}
}
