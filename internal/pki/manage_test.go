package pki

import "testing"

// TestValidateName is the security-relevant one: a common name becomes a
// filename under pki/issued and an argument to easyrsa.
func TestValidateName(t *testing.T) {
	ok := []string{"alice", "bob-2", "user_1", "a", "host.example", "A1"}
	for _, n := range ok {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) rejected a legitimate name: %v", n, err)
		}
	}

	bad := []string{
		"",                             // empty
		"../../etc/passwd",             // traversal
		"..",                           // traversal
		"a/b",                          // path separator
		"a\\b",                         // windows separator
		"-leading",                     // must start alphanumeric
		".hidden",                      // ditto
		"name with space",              // shell-ish
		"name;rm -rf /",                // command injection shape
		"name$(id)",                    // substitution shape
		"name\nsecond",                 // newline
		"ca",                           // reserved
		"server",                       // reserved
		"a" + string(make([]byte, 70)), // too long
	}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) accepted a dangerous name", n)
		}
	}
}

func TestValidateNameLength(t *testing.T) {
	long := ""
	for range 64 {
		long += "a"
	}
	if err := ValidateName(long); err != nil {
		t.Errorf("64 characters should be allowed: %v", err)
	}
	if err := ValidateName(long + "a"); err == nil {
		t.Error("65 characters should be rejected")
	}
}
