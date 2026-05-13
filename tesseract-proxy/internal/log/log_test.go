package log_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/log"
)

func TestNew_LevelsAccepted(t *testing.T) {
	cases := []string{"", "info", "INFO", "debug", "warn", "warning", "error"}
	for _, lvl := range cases {
		t.Run("level="+lvl, func(t *testing.T) {
			if _, err := log.New(log.Options{Level: lvl, Output: io.Discard}); err != nil {
				t.Fatalf("New(level=%q) failed: %v", lvl, err)
			}
		})
	}
}

func TestNew_FormatsAccepted(t *testing.T) {
	cases := []string{"", "json", "JSON", "text"}
	for _, fmt := range cases {
		t.Run("format="+fmt, func(t *testing.T) {
			if _, err := log.New(log.Options{Format: fmt, Output: io.Discard}); err != nil {
				t.Fatalf("New(format=%q) failed: %v", fmt, err)
			}
		})
	}
}

func TestNew_UnknownLevel(t *testing.T) {
	_, err := log.New(log.Options{Level: "verbose", Output: io.Discard})
	if err == nil {
		t.Fatal("expected error for unknown level, got nil")
	}
}

func TestNew_UnknownFormat(t *testing.T) {
	_, err := log.New(log.Options{Format: "yaml", Output: io.Discard})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestNew_NilOutput(t *testing.T) {
	_, err := log.New(log.Options{Level: "info", Format: "json"})
	if err == nil {
		t.Fatal("expected error for nil output, got nil")
	}
}

func TestNew_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	logger, err := log.New(log.Options{Level: "info", Format: "json", Output: &buf})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hello", "key", "value")

	dec := json.NewDecoder(strings.NewReader(buf.String()))
	var entry map[string]any
	if err := dec.Decode(&entry); err != nil {
		t.Fatalf("decode JSON: %v\nraw: %q", err, buf.String())
	}
	if entry["msg"] != "hello" {
		t.Errorf("msg = %v, want %q", entry["msg"], "hello")
	}
	if entry["key"] != "value" {
		t.Errorf("key = %v, want %q", entry["key"], "value")
	}
	if entry["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", entry["level"])
	}
}

func TestNew_DebugLevelEmitsDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, err := log.New(log.Options{Level: "debug", Format: "json", Output: &buf})
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("verbose message")
	if buf.Len() == 0 {
		t.Fatal("debug-level logger did not emit debug record")
	}
}

func TestNew_InfoLevelSuppressesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, err := log.New(log.Options{Level: "info", Format: "json", Output: &buf})
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("should not appear")
	if buf.Len() != 0 {
		t.Errorf("info-level logger emitted debug record: %q", buf.String())
	}
}
