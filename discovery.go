package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// scanWorkers is the number of concurrent subnet probes.
	scanWorkers = 64
	// scanConnectTimeout bounds the TCP pre-check before the HTTPS probe.
	scanConnectTimeout = 600 * time.Millisecond
	// scanHTTPTimeout bounds a single /info request.
	scanHTTPTimeout = 2 * time.Second
	// scanMinPrefix is the smallest subnet prefix that is swept in full;
	// anything larger falls back to the /24 around the local address.
	scanMinPrefix = 22
)

func discover(cfg *Config, timeout time.Duration) []DiscoveredDevice {
	var mu sync.Mutex
	found := make(map[string]DiscoveredDevice)
	var wg sync.WaitGroup

	wg.Go(func() {
		discoverMulticast(cfg, timeout, &mu, found)
	})

	if cfg.Scan {
		wg.Go(func() {
			discoverSubnet(cfg, timeout, &mu, found)
		})
	}

	wg.Wait()

	var results []DiscoveredDevice
	for _, d := range found {
		results = append(results, d)
	}
	return results
}

func sendMulticastAnnouncement(cfg *Config) error {
	addr, err := net.ResolveUDPAddr("udp", cfg.MulticastAddr)
	if err != nil {
		return fmt.Errorf("resolve multicast address: %w", err)
	}

	var conn *net.UDPConn
	if cfg.BindIface != nil {
		conn, err = net.ListenMulticastUDP("udp", cfg.BindIface, addr)
	} else {
		var laddr *net.UDPAddr
		if cfg.BindIP != "" {
			laddr = &net.UDPAddr{IP: net.ParseIP(cfg.BindIP)}
		}
		conn, err = net.DialUDP("udp", laddr, addr)
	}
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

	if cfg.BindIface != nil {
		_, err = conn.WriteToUDP(data, addr)
	} else {
		_, err = conn.Write(data)
	}
	if err != nil {
		return fmt.Errorf("write announcement: %w", err)
	}
	return nil
}

func announceLoop(cfg *Config, interval time.Duration, stop <-chan struct{}) {
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

	var conn *net.UDPConn
	if cfg.BindIface != nil {
		conn, err = net.ListenMulticastUDP("udp", cfg.BindIface, addr)
	} else {
		conn, err = net.ListenMulticastUDP("udp", nil, addr)
	}
	if err != nil {
		cfg.Logger.Debugf("Multicast listen failed: %v\n", err)
		return
	}
	defer conn.Close()

	cfg.Logger.Debugf("Multicast listening on %s\n", cfg.MulticastAddr)

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

	client := newHTTPClient(cfg)
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

func newHTTPClient(cfg *Config) *http.Client {
	return newHTTPClientWithTimeout(cfg, 5*time.Second)
}

// newHTTPClientWithTimeout builds a client that presents our self-signed
// certificate. LocalSend peers use mutual TLS and reject clients that offer
// none, so the certificate is required even though peer certs are not verified.
func newHTTPClientWithTimeout(cfg *Config, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	if len(cfg.TLSCert.Certificate) > 0 {
		// Not Certificates: peers ask for a certificate issued by a CA they
		// list, which our self-signed one never matches, so the default
		// selection would send nothing and the handshake would fail with
		// "certificate required". They accept any certificate in practice.
		cert := cfg.TLSCert
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

// discoverSubnet probes every host on the local subnet with the v2 info
// endpoint. The mobile apps answer a multicast announcement with an HTTP
// register call instead of a multicast reply, which never reaches us when the
// announcement is not seen, so the sweep finds them regardless.
func discoverSubnet(cfg *Config, timeout time.Duration, mu *sync.Mutex, found map[string]DiscoveredDevice) {
	targets, own, err := subnetTargets(cfg)
	if err != nil {
		cfg.Logger.Debugf("Subnet scan skipped: %v\n", err)
		return
	}
	cfg.Logger.Debugf("Scanning %d hosts around %s on port %d\n", len(targets), own, cfg.Port)

	httpTimeout := scanHTTPTimeout
	if timeout < httpTimeout {
		httpTimeout = timeout
	}
	client := newHTTPClientWithTimeout(cfg, httpTimeout)
	defer client.CloseIdleConnections()

	deadline := time.Now().Add(timeout)
	queue := make(chan string)
	var wg sync.WaitGroup

	for range scanWorkers {
		wg.Go(func() {
			for ip := range queue {
				if time.Now().After(deadline) {
					continue
				}
				info, ok := probeInfo(cfg, client, ip)
				if !ok {
					continue
				}
				mu.Lock()
				key := fmt.Sprintf("%s:%d", ip, info.Port)
				if _, exists := found[key]; !exists {
					found[key] = DiscoveredDevice{Info: info, IP: ip, Port: info.Port}
					cfg.Logger.Infof("Discovered via scan: %s at %s:%d\n", info.Alias, ip, info.Port)
				}
				mu.Unlock()
			}
		})
	}

	for _, ip := range targets {
		queue <- ip
	}
	close(queue)
	wg.Wait()
	cfg.Logger.Debugf("Subnet scan finished\n")
}

func probeInfo(cfg *Config, client *http.Client, ip string) (DeviceInfo, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, scanConnectTimeout)
	if err != nil {
		return DeviceInfo{}, false
	}
	conn.Close()

	target := fmt.Sprintf("https://%s/api/localsend/v2/info?fingerprint=%s", addr, url.QueryEscape(cfg.Fingerprint))
	cfg.Logger.Debugf("Probing %s\n", target)
	resp, err := client.Get(target)
	if err != nil {
		cfg.Logger.Debugf("Probe %s failed: %v\n", target, err)
		return DeviceInfo{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cfg.Logger.Debugf("Probe %s returned %d\n", target, resp.StatusCode)
		return DeviceInfo{}, false
	}

	var info DeviceInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		cfg.Logger.Debugf("Probe %s parse error: %v\n", target, err)
		return DeviceInfo{}, false
	}
	if info.Alias == "" {
		return DeviceInfo{}, false
	}
	if info.Fingerprint != "" && info.Fingerprint == cfg.Fingerprint {
		return DeviceInfo{}, false
	}
	// The v2 info response carries no port or protocol; it answered on ours.
	if info.Port == 0 {
		info.Port = cfg.Port
	}
	if info.Protocol == "" {
		info.Protocol = "https"
	}
	return info, true
}

// subnetTargets lists every host address on the local subnet except our own,
// and returns the local address alongside them.
func subnetTargets(cfg *Config) ([]string, string, error) {
	own := cfg.BindIP
	if own == "" {
		detected, err := autoDetectIP()
		if err != nil {
			return nil, "", err
		}
		own = detected
	}
	ownIP := net.ParseIP(own).To4()
	if ownIP == nil {
		return nil, "", fmt.Errorf("no IPv4 address to scan from (%q)", own)
	}

	mask := net.CIDRMask(24, 32)
	if cfg.BindIface != nil {
		addrs, _ := cfg.BindIface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || !ipnet.IP.To4().Equal(ownIP) {
				continue
			}
			if ones, bits := ipnet.Mask.Size(); bits == 32 && ones >= scanMinPrefix {
				mask = ipnet.Mask
			} else {
				cfg.Logger.Debugf("Subnet /%d too large, scanning a /24 instead\n", ones)
			}
			break
		}
	}

	network := binary.BigEndian.Uint32(ownIP.Mask(mask))
	ones, _ := mask.Size()
	broadcast := network | ^uint32(0)>>ones
	self := binary.BigEndian.Uint32(ownIP)

	var targets []string
	for host := network + 1; host < broadcast; host++ {
		if host == self {
			continue
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], host)
		targets = append(targets, net.IP(buf[:]).String())
	}
	return targets, own, nil
}

func listenMulticastContinuous(cfg *Config, stop <-chan struct{}) {
	addr, err := net.ResolveUDPAddr("udp", cfg.MulticastAddr)
	if err != nil {
		cfg.Logger.Debugf("Multicast listener resolve failed: %v\n", err)
		return
	}

	var conn *net.UDPConn
	if cfg.BindIface != nil {
		conn, err = net.ListenMulticastUDP("udp", cfg.BindIface, addr)
	} else {
		conn, err = net.ListenMulticastUDP("udp", nil, addr)
	}
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
			continue
		}

		cfg.Logger.Debugf("Multicast listener: packet from %s alias=%s announce=%v\n", src.IP, info.Alias, info.Announce)

		if info.Announce {
			cfg.Logger.Debugf("Multicast listener: sending register to %s:%d\n", src.IP, info.Port)
			go func(ip string, port int) {
				var dummy sync.Mutex
				dummyFound := make(map[string]DiscoveredDevice)
				registerDevice(cfg, ip, port, &dummy, dummyFound)
			}(src.IP.String(), info.Port)
		} else {
			cfg.Logger.Debugf("Multicast listener: response from %s (%s)\n", src.IP, info.Alias)
		}
	}
}
