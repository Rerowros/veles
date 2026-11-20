package outbound

import (
	"runtime"
	"time"
)

// P26: on iOS the QUIC clients (hysteria, hysteria2, tuic without an
// explicit heartbeat-interval) send no keep-alive pings. A ping every 10 s
// keeps the cellular radio in its high-power state for as long as such a node
// is selected. Without it the connection closes after the idle timeout (30 s
// for hysteria2) and the next request dials a new one: one extra round trip
// after a pause. Note: quic-go disables pings only with 0; a negative period
// would ping every 1.5 PTO.
var quicKeepAliveOff = quicKeepAliveOffOn(runtime.GOOS)

func quicKeepAliveOffOn(goos string) bool {
	return goos == "ios"
}

// quicKeepAlive returns period, or 0 (no pings) where pings are off.
func quicKeepAlive(period time.Duration) time.Duration {
	if quicKeepAliveOff {
		return 0
	}
	return period
}
