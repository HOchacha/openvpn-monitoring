package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withFlags swaps in a private flag set so tests do not disturb each other or
// the real command line.
func withFlags(t *testing.T) (listen *string, retention *time.Duration) {
	t.Helper()

	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })

	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.NewFile(0, os.DevNull))
	listen = flag.String("listen", "127.0.0.1:9090", "")
	retention = flag.Duration("retention", time.Hour, "")
	flag.String("store", "", "")
	return listen, retention
}

func writeConf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ovpnmon.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigFileSetsValues(t *testing.T) {
	listen, retention := withFlags(t)

	path := writeConf(t, `
# a comment
; another comment

listen = 127.0.0.1:8888
retention = 48h
`)
	if err := loadConfigFile(path, nil); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if *listen != "127.0.0.1:8888" {
		t.Errorf("listen is %q", *listen)
	}
	if *retention != 48*time.Hour {
		t.Errorf("retention is %v", *retention)
	}
}

func TestCommandLineBeatsConfigFile(t *testing.T) {
	listen, retention := withFlags(t)

	path := writeConf(t, "listen = 127.0.0.1:8888\nretention = 48h\n")
	// Pretend -listen was given on the command line.
	if err := loadConfigFile(path, map[string]bool{"listen": true}); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if *listen != "127.0.0.1:9090" {
		t.Errorf("config file overrode an explicit flag: listen is %q", *listen)
	}
	if *retention != 48*time.Hour {
		t.Errorf("unset flag should still come from the file, got %v", *retention)
	}
}

// TestUnknownKeyIsAnError is the point of validating at all: a typo in a config
// file is otherwise invisible until someone notices a setting never applied.
func TestUnknownKeyIsAnError(t *testing.T) {
	withFlags(t)

	path := writeConf(t, "listen = 127.0.0.1:8888\nretenshun = 48h\n")
	err := loadConfigFile(path, nil)
	if err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if got := err.Error(); !strings.Contains(got, "retenshun") || !strings.Contains(got, ":2") {
		t.Errorf("error should name the key and line, got %q", got)
	}
}

func TestMalformedLineIsAnError(t *testing.T) {
	withFlags(t)

	if err := loadConfigFile(writeConf(t, "listen 127.0.0.1:8888\n"), nil); err == nil {
		t.Error("a line without '=' was accepted")
	}
}

func TestInvalidValueIsAnError(t *testing.T) {
	withFlags(t)

	if err := loadConfigFile(writeConf(t, "retention = forever\n"), nil); err == nil {
		t.Error("an unparseable duration was accepted")
	}
}

func TestConfigCannotSetConfig(t *testing.T) {
	withFlags(t)
	flag.String("config", "", "")

	if err := loadConfigFile(writeConf(t, "config = /elsewhere.conf\n"), nil); err == nil {
		t.Error("a config file was allowed to redirect to another config file")
	}
}

func TestQuotedAndSpacedValues(t *testing.T) {
	withFlags(t)

	path := writeConf(t, `store  =  "sqlite:/opt/ovpnmon/data/history.db"  `)
	if err := loadConfigFile(path, nil); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if got := flag.Lookup("store").Value.String(); got != "sqlite:/opt/ovpnmon/data/history.db" {
		t.Errorf("value is %q; quotes and padding should be stripped", got)
	}
}
