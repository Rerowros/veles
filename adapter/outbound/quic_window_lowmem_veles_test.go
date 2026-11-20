//go:build with_low_memory

package outbound

import (
	"testing"

	"github.com/metacubex/quic-go"
)

// P26: with the with_low_memory tag the adapters' hook really caps.
func TestQUICWindowCeilingLowMemoryBuild(t *testing.T) {
	cfg := quic.Config{MaxStreamReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 20 << 20}
	capQUICReceiveWindows(&cfg)
	if cfg.MaxStreamReceiveWindow != lowMemoryStreamReceiveWindow || cfg.MaxConnectionReceiveWindow != lowMemoryConnectionReceiveWindow {
		t.Fatalf("got %d/%d, want the low-memory ceiling", cfg.MaxStreamReceiveWindow, cfg.MaxConnectionReceiveWindow)
	}
}

// P26: the tuic adapter calls the hook (its defaults are 15 / 64 MB).
func TestQUICWindowCeilingTuicWired(t *testing.T) {
	p, err := NewTuic(TuicOption{Name: "t", Server: "127.0.0.1", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if p.quicConfig.MaxStreamReceiveWindow != lowMemoryStreamReceiveWindow || p.quicConfig.MaxConnectionReceiveWindow != lowMemoryConnectionReceiveWindow {
		t.Fatalf("tuic windows %d/%d, want the low-memory ceiling", p.quicConfig.MaxStreamReceiveWindow, p.quicConfig.MaxConnectionReceiveWindow)
	}
}
