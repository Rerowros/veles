package keepalive

import "testing"

// P26: phones never send TCP keepalive probes, whatever the config says.
func TestForceDisableOnPhones(t *testing.T) {
	for goos, want := range map[string]bool{
		"android": true,
		"ios":     true,
		"darwin":  false,
		"linux":   false,
		"windows": false,
	} {
		if got := forceDisableOn(goos); got != want {
			t.Errorf("forceDisableOn(%q) = %v, want %v", goos, got, want)
		}
	}
}
