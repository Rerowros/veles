package keepalive

import (
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
)

var (
	keepAliveIdle     = atomic.NewInt64(0)
	keepAliveInterval = atomic.NewInt64(0)
	disableKeepAlive  = atomic.NewBool(false)
)

func SetKeepAliveIdle(t time.Duration) {
	keepAliveIdle.Store(int64(t))
}

func SetKeepAliveInterval(t time.Duration) {
	keepAliveInterval.Store(int64(t))
}

func KeepAliveIdle() time.Duration {
	return time.Duration(keepAliveIdle.Load())
}

func KeepAliveInterval() time.Duration {
	return time.Duration(keepAliveInterval.Load())
}

func SetDisableKeepAlive(disable bool) {
	if forceDisableOn(runtime.GOOS) {
		setDisableKeepAlive(true)
	} else {
		setDisableKeepAlive(disable)
	}
}

// forceDisableOn reports whether TCP keepalive is always off on goos.
// P26 adds ios to upstream's android: with the system default a probe every
// 15 s on each quiet connection to the node keeps the cellular radio awake for
// as long as the VPN is on.
func forceDisableOn(goos string) bool {
	return goos == "android" || goos == "ios"
}

func setDisableKeepAlive(disable bool) {
	disableKeepAlive.Store(disable)
}

func DisableKeepAlive() bool {
	return disableKeepAlive.Load()
}

func SetNetDialer(dialer *net.Dialer) {
	setNetDialer(dialer)
}

func SetNetListenConfig(lc *net.ListenConfig) {
	setNetListenConfig(lc)
}

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(TCPConn); ok && tcp != nil {
		tcpKeepAlive(tcp)
	}
}
