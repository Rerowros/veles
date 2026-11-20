package outbound

import (
	"testing"
	"time"
)

// P26: QUIC keep-alive pings are off on iOS only.
func TestQUICKeepAliveOffOnIOS(t *testing.T) {
	for goos, want := range map[string]bool{"ios": true, "android": false, "darwin": false, "linux": false, "windows": false} {
		if got := quicKeepAliveOffOn(goos); got != want {
			t.Errorf("quicKeepAliveOffOn(%q) = %v, want %v", goos, got, want)
		}
	}
}

// P26: tuic without heartbeat-interval follows quicKeepAlive (0 on iOS, 10 s
// elsewhere); an explicit heartbeat-interval is kept everywhere.
func TestQUICKeepAliveTuic(t *testing.T) {
	saved := quicKeepAliveOff
	defer func() { quicKeepAliveOff = saved }()
	opt := func(hb int) TuicOption {
		return TuicOption{Name: "t", Server: "127.0.0.1", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Password: "p", HeartbeatInterval: hb}
	}
	for _, tc := range []struct {
		off  bool
		hb   int
		want time.Duration
	}{
		{off: true, hb: 0, want: 0},
		{off: false, hb: 0, want: 10 * time.Second},
		{off: true, hb: 25000, want: 25 * time.Second},
		{off: false, hb: 25000, want: 25 * time.Second},
	} {
		quicKeepAliveOff = tc.off
		p, err := NewTuic(opt(tc.hb))
		if err != nil {
			t.Fatal(err)
		}
		if p.quicConfig.KeepAlivePeriod != tc.want {
			t.Errorf("off=%v heartbeat=%d: keep-alive %v, want %v", tc.off, tc.hb, p.quicConfig.KeepAlivePeriod, tc.want)
		}
	}
}
