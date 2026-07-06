package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// receive starts an HTTPS server to accept incoming transfers.
// It prompts on stderr and reads stdin for accept/deny decisions.
// It also periodically sends multicast announcements so other devices can find it.
func receive(cfg *Config, announceInterval time.Duration) error {
	var stdinMu sync.Mutex
	reader := bufio.NewReader(os.Stdin)

	// Start background announcement loop
	stopAnnounce := make(chan struct{})
	go announceLoop(cfg, announceInterval, stopAnnounce)
	defer close(stopAnnounce)

	// Start background multicast listener to catch other devices' announcements
	stopListener := make(chan struct{})
	go listenMulticastContinuous(cfg, stopListener)
	defer close(stopListener)

	mux := http.NewServeMux()

	var (
		sessionMu     sync.Mutex
		activeSession *ReceiveSession
	)

	mux.HandleFunc("/api/localsend/v2/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			cfg.Logger.Debugf("Register: method not allowed: %s\n", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var peer DeviceInfo
		if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
			cfg.Logger.Debugf("Register: invalid body: %v\n", err)
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		cfg.Logger.Debugf("Register from %s: alias=%s\n", r.RemoteAddr, peer.Alias)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceInfo{
			Alias:       cfg.Alias,
			Version:     protocolVersion,
			DeviceType:  cfg.DeviceType,
			DeviceModel: cfg.DeviceModel,
			Fingerprint: cfg.Fingerprint,
			Port:        cfg.Port,
			Protocol:    cfg.Protocol,
			Download:    false,
		})
	})

	mux.HandleFunc("/api/localsend/v2/prepare-upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			cfg.Logger.Debugf("Prepare-upload: method not allowed: %s\n", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req PrepareUploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			cfg.Logger.Debugf("Prepare-upload: invalid body: %v\n", err)
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		cfg.Logger.Infof("Incoming transfer from %s (%s) at %s\n", req.Info.Alias, req.Info.DeviceType, r.RemoteAddr)
		for _, f := range req.Files {
			cfg.Logger.Infof("  - %s (%d bytes)\n", f.FileName, f.Size)
		}

		fmt.Fprintf(os.Stdout, "\nIncoming transfer from: %s (%s)\n", req.Info.Alias, req.Info.DeviceType)
		fmt.Fprintf(os.Stdout, "Files:\n")
		for _, f := range req.Files {
			fmt.Fprintf(os.Stdout, "  - %s (%d bytes)\n", f.FileName, f.Size)
		}
		fmt.Fprintf(os.Stdout, "Accept? (yes/no): ")
		os.Stdout.Sync()

		stdinMu.Lock()
		line, err := reader.ReadString('\n')
		stdinMu.Unlock()
		if err != nil {
			cfg.Logger.Errorf("Failed to read stdin: %v\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "yes" && line != "y" {
			cfg.Logger.Infof("Transfer denied by user\n")
			fmt.Fprintf(os.Stdout, "Transfer denied.\n")
			http.Error(w, "Rejected", http.StatusForbidden)
			return
		}

		sessionID := generateFileID()
		tokens := make(map[string]string)
		for id := range req.Files {
			tokens[id] = generateFileID()
		}

		sessionMu.Lock()
		activeSession = &ReceiveSession{
			SessionID: sessionID,
			Files:     req.Files,
			Tokens:    tokens,
		}
		sessionMu.Unlock()

		cfg.Logger.Infof("Transfer accepted, session=%s\n", sessionID)
		fmt.Fprintf(os.Stdout, "Transfer accepted.\n")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PrepareUploadResponse{
			SessionID: sessionID,
			Files:     tokens,
		})
	})

	mux.HandleFunc("/api/localsend/v2/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			cfg.Logger.Debugf("Upload: method not allowed: %s\n", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		sessionID := q.Get("sessionId")
		fileID := q.Get("fileId")
		token := q.Get("token")

		sessionMu.Lock()
		session := activeSession
		sessionMu.Unlock()

		if session == nil || session.SessionID != sessionID {
			cfg.Logger.Debugf("Upload: invalid session %s\n", sessionID)
			http.Error(w, "Invalid session", http.StatusForbidden)
			return
		}
		expectedToken, ok := session.Tokens[fileID]
		if !ok || expectedToken != token {
			cfg.Logger.Debugf("Upload: invalid token for file %s\n", fileID)
			http.Error(w, "Invalid token", http.StatusForbidden)
			return
		}
		meta, ok := session.Files[fileID]
		if !ok {
			cfg.Logger.Debugf("Upload: invalid file id %s\n", fileID)
			http.Error(w, "Invalid file", http.StatusForbidden)
			return
		}

		fileName := filepath.Base(meta.FileName)
		if fileName == "" || fileName == "." || fileName == ".." {
			cfg.Logger.Warnf("Upload: rejected suspicious filename %q\n", meta.FileName)
			http.Error(w, "Invalid filename", http.StatusBadRequest)
			return
		}

		outPath := filepath.Join(cfg.DownloadDir, fileName)
		out, err := os.Create(outPath)
		if err != nil {
			cfg.Logger.Errorf("Upload: failed to create file %s: %v\n", outPath, err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		pw := &progressWriter{
			Writer:       out,
			Total:        meta.Size,
			Logger:       cfg.Logger,
			FileName:     fileName,
		}

		n, err := io.Copy(pw, r.Body)
		if err != nil {
			cfg.Logger.Errorf("Upload: error receiving %s: %v\n", fileName, err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		cfg.Logger.Infof("Received: %s (%d bytes)\n", fileName, n)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/localsend/v2/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			cfg.Logger.Debugf("Cancel: method not allowed: %s\n", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sessionMu.Lock()
		activeSession = nil
		sessionMu.Unlock()
		cfg.Logger.Debugf("Session cancelled\n")
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cfg.TLSCert},
		},
	}

	cfg.Logger.Infof("Receiving on https://0.0.0.0:%d (fingerprint: %s)\n", cfg.Port, cfg.Fingerprint)
	cfg.Logger.Infof("Announcing every %s on %s\n", announceInterval, cfg.MulticastAddr)
	cfg.Logger.Infof("Downloads will be saved to: %s\n", cfg.DownloadDir)
	return server.ListenAndServeTLS("", "")
}

// progressWriter wraps an io.Writer to log transfer progress.
type progressWriter struct {
	Writer       io.Writer
	Total        int64
	BytesWritten int64
	Logger       *Logger
	FileName     string
	lastLog      time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.Writer.Write(p)
	if n > 0 {
		pw.BytesWritten += int64(n)
		if time.Since(pw.lastLog) > 2*time.Second || pw.BytesWritten == pw.Total {
			pw.lastLog = time.Now()
			pct := float64(pw.BytesWritten) * 100 / float64(pw.Total)
			pw.Logger.Infof("  %s: %.1f%% (%d/%d bytes)\n", pw.FileName, pct, pw.BytesWritten, pw.Total)
		}
	}
	return n, err
}

