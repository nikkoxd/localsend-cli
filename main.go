package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		alias            = flag.String("alias", defaultAlias, "Device alias shown to peers")
		port             = flag.Int("port", defaultPort, "TCP port for HTTPS server")
		multicast        = flag.String("multicast", defaultMulticastAddr, "UDP multicast address for discovery")
		downloadDir      = flag.String("dir", defaultDownloadDir(), "Downloads folder for received files")
		timeout          = flag.Duration("timeout", 5*time.Second, "Discovery timeout")
		jsonOut          = flag.Bool("json", false, "Output discovery results as JSON")
		pin              = flag.String("pin", "", "PIN for transfers (optional)")
		toAddr           = flag.String("to", "", "Target address ip:port or alias for send mode")
		verbose          = flag.Bool("v", false, "Enable verbose (debug) logging")
		quiet            = flag.Bool("q", false, "Suppress non-error log output")
		announceInterval = flag.Duration("announce", 5*time.Second, "Interval between multicast announcements in receive mode")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: localsend-cli [options] <command> [options] [files...]

Commands:
  send      Send files to a device (requires -to, or auto-discovers)
  receive   Start receiving files
  discover  Discover nearby devices

Global options (before or after command):
`)
		flag.PrintDefaults()
	}

	// Custom parsing: allow flags before AND after the subcommand
	// First, find where the subcommand is (first non-flag arg)
	cmdIdx := 1 // skip program name
	for cmdIdx < len(os.Args) {
		arg := os.Args[cmdIdx]
		if !strings.HasPrefix(arg, "-") {
			break
		}
		// Skip flag values (e.g., -to value)
		if arg == "-to" || arg == "--to" ||
			arg == "-alias" || arg == "--alias" ||
			arg == "-port" || arg == "--port" ||
			arg == "-multicast" || arg == "--multicast" ||
			arg == "-dir" || arg == "--dir" ||
			arg == "-timeout" || arg == "--timeout" ||
			arg == "-pin" || arg == "--pin" ||
			arg == "-announce" || arg == "--announce" {
			cmdIdx++
			if cmdIdx < len(os.Args) && !strings.HasPrefix(os.Args[cmdIdx], "-") {
				cmdIdx++
			}
		} else if strings.Contains(arg, "=") {
			cmdIdx++
		} else {
			cmdIdx++
		}
	}

	// Parse all flags (both before and after subcommand)
	var allArgs []string
	allArgs = append(allArgs, os.Args[0])
	if cmdIdx < len(os.Args) {
		// Flags before command
		allArgs = append(allArgs, os.Args[1:cmdIdx]...)
		// Flags after command
		allArgs = append(allArgs, os.Args[cmdIdx+1:]...)
	} else {
		allArgs = append(allArgs, os.Args[1:]...)
	}
	flag.CommandLine.Parse(allArgs[1:])

	if cmdIdx >= len(os.Args) {
		flag.Usage()
		os.Exit(1)
	}
	cmd := os.Args[cmdIdx]
	// Remaining args after command (files, etc.)
	remainingArgs := os.Args[cmdIdx+1:]
	// Filter out any flags from remainingArgs (they were already parsed)
	var files []string
	for i := 0; i < len(remainingArgs); i++ {
		arg := remainingArgs[i]
		if strings.HasPrefix(arg, "-") {
			// Skip flag and its value
			if arg == "-to" || arg == "--to" ||
				arg == "-alias" || arg == "--alias" ||
				arg == "-port" || arg == "--port" ||
				arg == "-multicast" || arg == "--multicast" ||
				arg == "-dir" || arg == "--dir" ||
				arg == "-timeout" || arg == "--timeout" ||
				arg == "-pin" || arg == "--pin" ||
				arg == "-announce" || arg == "--announce" {
				i++
			}
			continue
		}
		files = append(files, arg)
	}

	// Configure logger
	logLevel := LevelInfo
	if *quiet {
		logLevel = LevelError
	} else if *verbose {
		logLevel = LevelDebug
	}
	logger := NewLogger(os.Stdout, logLevel)

	cfg := &Config{
		Alias:         *alias,
		Port:          *port,
		MulticastAddr: *multicast,
		DownloadDir:   *downloadDir,
		Protocol:      "https",
		DeviceType:    defaultDeviceType,
		DeviceModel:   "Go CLI",
		Logger:        logger,
	}

	if err := os.MkdirAll(cfg.DownloadDir, 0755); err != nil {
		logger.Errorf("Failed to create download directory: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("Generating self-signed TLS certificate...\n")
	cert, certDER, fingerprint, err := generateSelfSignedCert()
	if err != nil {
		logger.Errorf("Failed to generate TLS certificate: %v\n", err)
		os.Exit(1)
	}
	cfg.TLSCert = cert
	cfg.CertDER = certDER
	cfg.Fingerprint = fingerprint
	logger.Debugf("Certificate fingerprint: %s\n", fingerprint)

	switch cmd {
	case "send":
		if len(files) == 0 {
			logger.Errorf("No files specified for send\n")
			os.Exit(1)
		}
		if *toAddr == "" {
			logger.Infof("No target specified, starting discovery...\n")
			devices := discover(cfg, *timeout)
			if len(devices) == 0 {
				logger.Errorf("No devices found. Use -to to specify target address or alias.\n")
				os.Exit(1)
			}
			target := devices[0]
			*toAddr = fmt.Sprintf("%s:%d", target.IP, target.Port)
			logger.Infof("Auto-selected device: %s (%s)\n", target.Info.Alias, *toAddr)
		} else if !strings.Contains(*toAddr, ":") {
			// -to is an alias, not an IP:port
			logger.Infof("Looking up alias %q...\n", *toAddr)
			devices := discover(cfg, *timeout)
			var matches []DiscoveredDevice
			for _, d := range devices {
				if strings.EqualFold(d.Info.Alias, *toAddr) {
					matches = append(matches, d)
				}
			}
			if len(matches) == 0 {
				logger.Errorf("No device found with alias %q\n", *toAddr)
				os.Exit(1)
			}
			if len(matches) > 1 {
				logger.Errorf("Multiple devices match alias %q:\n", *toAddr)
				for _, m := range matches {
					logger.Errorf("  %s at %s:%d\n", m.Info.Alias, m.IP, m.Port)
				}
				os.Exit(1)
			}
			target := matches[0]
			*toAddr = fmt.Sprintf("%s:%d", target.IP, target.Port)
			logger.Infof("Resolved alias %q to %s\n", target.Info.Alias, *toAddr)
		}
		err := sendFiles(cfg, *toAddr, files, *pin, *jsonOut)
		if *jsonOut {
			result := SendResult{
				Target: *toAddr,
				Files:  files,
			}
			if err != nil {
				result.Success = false
				result.Error = err.Error()
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(result)
				os.Exit(1)
			}
			result.Success = true
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
		} else {
			if err != nil {
				logger.Errorf("Send failed: %v\n", err)
				os.Exit(1)
			}
			logger.Infof("Transfer complete\n")
		}
	case "receive":
		if err := receive(cfg, *announceInterval, *jsonOut); err != nil {
			logger.Errorf("Receive failed: %v\n", err)
			os.Exit(1)
		}
	case "discover":
		logger.Infof("Discovering devices (timeout %s)...\n", timeout)
		devices := discover(cfg, *timeout)
		logger.Infof("Found %d device(s)\n", len(devices))
		if *jsonOut {
			// Flatten: merge IP/Port into DeviceInfo for cleaner output
			var flat []map[string]any
			for _, d := range devices {
				m := map[string]any{
					"ip":          d.IP,
					"alias":       d.Info.Alias,
					"version":     d.Info.Version,
					"deviceModel": d.Info.DeviceModel,
					"deviceType":  d.Info.DeviceType,
					"fingerprint": d.Info.Fingerprint,
					"port":        d.Port,
					"protocol":    d.Info.Protocol,
					"download":    d.Info.Download,
				}
				flat = append(flat, m)
			}
			output := map[string]any{
				"count":   len(devices),
				"devices": flat,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(output)
		} else {
			for _, d := range devices {
				fmt.Printf("%s\t%s\t%s:%d\n", d.Info.Alias, d.Info.DeviceType, d.IP, d.Port)
			}
		}
	default:
		flag.Usage()
		os.Exit(1)
	}
}

