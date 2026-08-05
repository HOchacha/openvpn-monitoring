package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An indefinite block must not serialise as year 1: any consumer comparing
// that against now reads it as already expired.
func TestBlockJSONOmitsAZeroExpiry(t *testing.T) {
	raw, err := json.Marshal(Block{CommonName: "alice", CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), "until") {
		t.Errorf("an indefinite block carries an expiry: %s", raw)
	}
	if strings.Contains(string(raw), "0001-01-01") {
		t.Errorf("year 1 leaked into the JSON: %s", raw)
	}
}

func TestBlockJSONKeepsARealExpiry(t *testing.T) {
	until := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, err := json.Marshal(Block{CommonName: "alice", Until: until, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), "2030-01-02T03:04:05Z") {
		t.Errorf("expiry missing from the JSON: %s", raw)
	}

	var back Block
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !back.Until.Equal(until) {
		t.Errorf("round trip changed the expiry: %v != %v", back.Until, until)
	}
}
