package outbound

import (
	"github.com/metacubex/mihomo/constant/features"

	"github.com/metacubex/quic-go"
)

// P26: in with_low_memory builds (the iOS Network Extension, killed by the
// system at ~50 MB) the QUIC receive windows get a ceiling. The protocol
// defaults let one connection buffer up to 20 MB (hysteria2) or 64 MB
// (hysteria) of data the app has not read yet. 2 MB per stream and 4 MB per
// connection still carry ~160 / ~330 Mbit/s at 100 ms RTT.
const (
	lowMemoryStreamReceiveWindow     = 2 << 20
	lowMemoryConnectionReceiveWindow = 4 << 20
)

// capQUICReceiveWindows applies the ceiling when the build is low-memory. A
// window left at 0 (the protocol default fills it later) gets the ceiling as
// its maximum and a quarter of it as its starting size.
func capQUICReceiveWindows(cfg *quic.Config) {
	capQUICReceiveWindowFields(&cfg.InitialStreamReceiveWindow, &cfg.MaxStreamReceiveWindow,
		&cfg.InitialConnectionReceiveWindow, &cfg.MaxConnectionReceiveWindow)
}

// capQUICReceiveWindowFields is capQUICReceiveWindows for any QUIC fork's
// config (shadowquic uses jls-quic-go).
func capQUICReceiveWindowFields(initStream, maxStream, initConn, maxConn *uint64) {
	if features.WithLowMemory {
		capWindowsTo(initStream, maxStream, initConn, maxConn, lowMemoryStreamReceiveWindow, lowMemoryConnectionReceiveWindow)
	}
}

func capQUICReceiveWindowsTo(cfg *quic.Config, stream, conn uint64) {
	capWindowsTo(&cfg.InitialStreamReceiveWindow, &cfg.MaxStreamReceiveWindow,
		&cfg.InitialConnectionReceiveWindow, &cfg.MaxConnectionReceiveWindow, stream, conn)
}

func capWindowsTo(initStream, maxStream, initConn, maxConn *uint64, stream, conn uint64) {
	*maxStream = ceilWindow(*maxStream, stream)
	*initStream = startWindow(*initStream, *maxStream)
	*maxConn = ceilWindow(*maxConn, conn)
	*initConn = startWindow(*initConn, *maxConn)
}

func ceilWindow(v, ceiling uint64) uint64 {
	if v == 0 || v > ceiling {
		return ceiling
	}
	return v
}

func startWindow(v, max uint64) uint64 {
	if v == 0 {
		return max / 4
	}
	if v > max {
		return max
	}
	return v
}
