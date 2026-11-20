package outbound

import (
	"testing"

	"github.com/metacubex/quic-go"
)

// P26: ceilings for QUIC receive windows (low-memory builds).
func TestQUICWindowCeiling(t *testing.T) {
	const s, c = 2 << 20, 4 << 20
	cases := []struct {
		name string
		in   quic.Config
		want quic.Config
	}{
		{
			name: "zero (hysteria2 fills defaults later) gets the ceiling",
			in:   quic.Config{},
			want: quic.Config{InitialStreamReceiveWindow: s / 4, MaxStreamReceiveWindow: s, InitialConnectionReceiveWindow: c / 4, MaxConnectionReceiveWindow: c},
		},
		{
			name: "hysteria defaults (15 / 64 MB) are lowered",
			in:   quic.Config{InitialStreamReceiveWindow: 15728640 / 10, MaxStreamReceiveWindow: 15728640, InitialConnectionReceiveWindow: 67108864 / 10, MaxConnectionReceiveWindow: 67108864},
			want: quic.Config{InitialStreamReceiveWindow: 1572864, MaxStreamReceiveWindow: s, InitialConnectionReceiveWindow: c, MaxConnectionReceiveWindow: c},
		},
		{
			name: "small explicit values stay",
			in:   quic.Config{InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 2 << 20},
			want: quic.Config{InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 2 << 20},
		},
		{
			name: "starting window never above the maximum",
			in:   quic.Config{InitialStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 20 << 20},
			want: quic.Config{InitialStreamReceiveWindow: s, MaxStreamReceiveWindow: s, InitialConnectionReceiveWindow: c, MaxConnectionReceiveWindow: c},
		},
	}
	for _, tc := range cases {
		got := tc.in
		capQUICReceiveWindowsTo(&got, s, c)
		if got.InitialStreamReceiveWindow != tc.want.InitialStreamReceiveWindow ||
			got.MaxStreamReceiveWindow != tc.want.MaxStreamReceiveWindow ||
			got.InitialConnectionReceiveWindow != tc.want.InitialConnectionReceiveWindow ||
			got.MaxConnectionReceiveWindow != tc.want.MaxConnectionReceiveWindow {
			t.Errorf("%s: got stream %d/%d conn %d/%d, want stream %d/%d conn %d/%d", tc.name,
				got.InitialStreamReceiveWindow, got.MaxStreamReceiveWindow, got.InitialConnectionReceiveWindow, got.MaxConnectionReceiveWindow,
				tc.want.InitialStreamReceiveWindow, tc.want.MaxStreamReceiveWindow, tc.want.InitialConnectionReceiveWindow, tc.want.MaxConnectionReceiveWindow)
		}
	}
}
