package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func sendFiles(cfg *Config, targetAddr string, files []string, pin string) error {
	// Use a longer timeout for prepare-upload since receiver waits for stdin
	prepareClient := newHTTPClientWithTimeout(60 * time.Second)
	// Normal client for uploads
	client := newHTTPClient()

	fileMap := make(map[string]FileMetadata)
	idToPath := make(map[string]string)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		id := generateFileID()
		fileMap[id] = FileMetadata{
			ID:       id,
			FileName: filepath.Base(path),
			Size:     info.Size(),
			FileType: mime.TypeByExtension(filepath.Ext(path)),
		}
		idToPath[id] = path
		cfg.Logger.Debugf("Prepared file %s -> id=%s size=%d\n", path, id, info.Size())
	}

	reqBody := PrepareUploadRequest{
		Info: DeviceInfo{
			Alias:       cfg.Alias,
			Version:     protocolVersion,
			DeviceType:  cfg.DeviceType,
			DeviceModel: cfg.DeviceModel,
			Fingerprint: cfg.Fingerprint,
			Port:        cfg.Port,
			Protocol:    cfg.Protocol,
			Download:    false,
		},
		Files: fileMap,
	}
	data, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("https://%s/api/localsend/v2/prepare-upload", targetAddr)
	if pin != "" {
		url += "?pin=" + pin
		cfg.Logger.Debugf("Using PIN authentication\n")
	}
	cfg.Logger.Debugf("POST %s\n", url)
	resp, err := prepareClient.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("prepare-upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("prepare-upload failed: %d %s", resp.StatusCode, string(body))
	}

	var prepResp PrepareUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&prepResp); err != nil {
		return fmt.Errorf("decode prepare-upload response: %w", err)
	}
	cfg.Logger.Debugf("Session established: %s\n", prepResp.SessionID)

	for id, meta := range fileMap {
		token, ok := prepResp.Files[id]
		if !ok {
			cfg.Logger.Warnf("Server did not accept file %s\n", meta.FileName)
			continue
		}
		path := idToPath[id]
		uploadURL := fmt.Sprintf("https://%s/api/localsend/v2/upload?sessionId=%s&fileId=%s&token=%s",
			targetAddr, prepResp.SessionID, id, token)

		cfg.Logger.Infof("Sending %s (%d bytes)...\n", meta.FileName, meta.Size)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		stat, _ := f.Stat()

		pr := &progressReader{
			Reader:   f,
			Total:    stat.Size(),
			Logger:   cfg.Logger,
			FileName: meta.FileName,
		}

		req, err := http.NewRequest("POST", uploadURL, pr)
		if err != nil {
			f.Close()
			return fmt.Errorf("create upload request: %w", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = stat.Size()

		uploadResp, err := client.Do(req)
		f.Close()
		if err != nil {
			return fmt.Errorf("upload %s failed: %w", meta.FileName, err)
		}
		uploadResp.Body.Close()
		if uploadResp.StatusCode != http.StatusOK {
			return fmt.Errorf("upload %s failed: %d", meta.FileName, uploadResp.StatusCode)
		}
		cfg.Logger.Infof("Sent: %s\n", meta.FileName)
	}
	return nil
}

func generateFileID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// progressReader wraps an io.Reader to log transfer progress.
type progressReader struct {
	Reader    io.Reader
	Total     int64
	BytesRead int64
	Logger    *Logger
	FileName  string
	lastLog   time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	if n > 0 {
		pr.BytesRead += int64(n)
		if time.Since(pr.lastLog) > 2*time.Second || pr.BytesRead == pr.Total {
			pr.lastLog = time.Now()
			pct := float64(pr.BytesRead) * 100 / float64(pr.Total)
			pr.Logger.Infof("  %s: %.1f%% (%d/%d bytes)\n", pr.FileName, pct, pr.BytesRead, pr.Total)
		}
	}
	return n, err
}
