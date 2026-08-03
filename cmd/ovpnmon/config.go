package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// defaultConfigPath is where ovpnmon looks when -config is not given. Missing
// is fine there; missing is an error when the path was asked for explicitly.
const defaultConfigPath = "/opt/ovpnmon/etc/ovpnmon.conf"

// loadConfigFile applies "key = value" settings to any flag the command line
// did not already set, so precedence runs command line > file > default.
//
// Keys are flag names, which keeps the file and -help in step: anything in one
// is spelled the same in the other. An unknown key is an error rather than a
// silent no-op, because a typo in a config file is otherwise invisible until
// someone notices the setting never took effect.
func loadConfigFile(path string, explicit map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	known := map[string]bool{}
	flag.VisitAll(func(fl *flag.Flag) { known[fl.Name] = true })

	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}

		key, value, found := strings.Cut(text, "=")
		if !found {
			return fmt.Errorf("%s:%d: expected key = value, got %q", path, line, text)
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		switch {
		case !known[key]:
			return fmt.Errorf("%s:%d: unknown setting %q", path, line, key)
		case key == "config":
			return fmt.Errorf("%s:%d: a config file cannot set %q", path, line, key)
		case explicit[key]:
			continue // the command line wins
		}

		if err := flag.Set(key, value); err != nil {
			return fmt.Errorf("%s:%d: %s: %w", path, line, key, err)
		}
	}
	return sc.Err()
}

// applyConfig resolves the config file against the flags already parsed.
func applyConfig(path string) error {
	explicit := map[string]bool{}
	flag.Visit(func(fl *flag.Flag) { explicit[fl.Name] = true })

	err := loadConfigFile(path, explicit)
	switch {
	case err == nil:
		return nil
	case os.IsNotExist(err) && !explicit["config"]:
		// No file at the default location just means "use flags and defaults".
		return nil
	default:
		return fmt.Errorf("reading config: %w", err)
	}
}
