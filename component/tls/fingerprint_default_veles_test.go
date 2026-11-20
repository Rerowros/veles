package tls

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"

	utls "github.com/metacubex/utls"
)

// P29: a TLS client to a proxy server without client-fingerprint is chrome,
// as in Xray; names are trimmed and case-insensitive; only "none" is Go TLS.
func TestVelesGetClientFingerprintDefaults(t *testing.T) {
	for _, name := range []string{"", "chrome", "Chrome", " chrome ", "CHROME\t"} {
		fingerprint, ok := GetClientFingerprint(name)
		if !ok || fingerprint != HelloChromeAuto {
			t.Fatalf("GetClientFingerprint(%q) = %v, %v; want chrome", name, fingerprint, ok)
		}
	}
	for _, name := range []string{"none", " None "} {
		if fingerprint, ok := GetClientFingerprint(name); ok {
			t.Fatalf("GetClientFingerprint(%q) = %v; want Go crypto/tls", name, fingerprint)
		}
	}
	if fingerprint, ok := GetClientFingerprint("Firefox"); !ok || fingerprint != utls.HelloFirefox_Auto {
		t.Fatalf("GetClientFingerprint(Firefox) = %v, %v; want firefox", fingerprint, ok)
	}
	// ShadowTLS, JLS and TLSMirror keep the old rules.
	if _, ok := GetFingerprint(""); ok {
		t.Fatal("GetFingerprint(\"\") must stay false")
	}
}

func TestVelesGetClientFingerprintUnknownWarnsAndUsesChrome(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	const typo = "chrom-p29-test"
	// The warning is once per process: forget an earlier run (go test -count=N).
	warnedClientFingerprints.Delete(typo)

	// waitWarning reads the log up to the sentinel and tells whether a
	// warning about typo came before it. The log channel is unbuffered and
	// read by one goroutine, so the order is the order of the calls.
	waitWarning := func(sentinel string) bool {
		log.Warnln("%s", sentinel)
		warned := false
		deadline := time.After(5 * time.Second)
		for {
			select {
			case event := <-sub:
				if event.LogLevel != log.WARNING {
					continue
				}
				if event.Payload == sentinel {
					return warned
				}
				// The warning quotes the name as written.
				if strings.Contains(strings.ToLower(event.Payload), typo) {
					warned = true
				}
			case <-deadline:
				t.Fatalf("no sentinel %q in the log", sentinel)
			}
		}
	}

	for i, wantWarning := range []bool{true, false} {
		// The second call differs in case and spaces: the same name for the warning.
		name := typo
		if i > 0 {
			name = " " + strings.ToUpper(typo) + " "
		}
		fingerprint, ok := GetClientFingerprint(name)
		if !ok || fingerprint != HelloChromeAuto {
			t.Fatalf("GetClientFingerprint(%q) = %v, %v; want chrome", name, fingerprint, ok)
		}
		if warned := waitWarning(fmt.Sprintf("p29-sentinel-%d", i)); warned != wantWarning {
			t.Fatalf("call %d with %q: warning = %v, want %v", i+1, name, warned, wantWarning)
		}
	}
}

// P29: "random" never picks iOS 14, whose hello has no X25519MLKEM768.
func TestVelesRandomFingerprintNeverIOS(t *testing.T) {
	for _, choice := range randomFingerprintPool {
		if choice.Item == "ios" {
			t.Fatal("ios is in the random pool")
		}
		fingerprint, ok := fingerprints[choice.Item]
		if !ok {
			t.Fatalf("random pool has unknown fingerprint %q", choice.Item)
		}
		if !FingerprintSupportsX25519MLKEM768(fingerprint) {
			t.Fatalf("random pool fingerprint %q has no X25519MLKEM768", choice.Item)
		}
	}
	for i := 0; i < 1000; i++ {
		if fingerprint := pickRandomFingerprint(); fingerprint.Client == utls.HelloIOS_Auto.Client {
			t.Fatalf("random picked %v", fingerprint)
		}
	}
}
