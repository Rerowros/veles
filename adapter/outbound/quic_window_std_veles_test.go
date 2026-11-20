//go:build !with_low_memory

package outbound

import (
	"testing"

	"github.com/metacubex/quic-go"
)

// P26: without the tag nothing changes.
func TestQUICWindowUntouchedStandardBuild(t *testing.T) {
	cfg := quic.Config{MaxStreamReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 20 << 20}
	capQUICReceiveWindows(&cfg)
	if cfg.MaxStreamReceiveWindow != 8<<20 || cfg.MaxConnectionReceiveWindow != 20<<20 || cfg.InitialStreamReceiveWindow != 0 {
		t.Fatalf("standard build changed the windows: %+v", cfg)
	}
}
