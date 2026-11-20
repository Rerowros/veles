package config

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// P29: client-fingerprint on the proxy wins; global-client-fingerprint stays
// removed (upstream logs an error and ignores it); otherwise chrome.
func TestVelesClientFingerprintPriority(t *testing.T) {
	for _, tc := range []struct {
		name, proxyLine string
		chrome          bool
	}{
		{"global-ignored-default-chrome", "", true},
		{"proxy-wins", "client-fingerprint: firefox", false},
		{"proxy-none", "client-fingerprint: none", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			recCh := make(chan []byte, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(conn, hdr); err != nil {
					return
				}
				rec := make([]byte, 5+int(binary.BigEndian.Uint16(hdr[3:5])))
				copy(rec, hdr)
				if _, err := io.ReadFull(conn, rec[5:]); err != nil {
					return
				}
				recCh <- rec
			}()

			raw := fmt.Sprintf(`
global-client-fingerprint: safari
proxies:
  - name: p
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: example.com
    skip-cert-verify: true
    %s
rules:
  - MATCH,p
`, ln.Addr().(*net.TCPAddr).Port, tc.proxyLine)
			cfg, err := Parse([]byte(raw))
			require.NoError(t, err)
			defer func() {
				for _, p := range cfg.Proxies {
					_ = p.Close()
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				if conn, err := cfg.Proxies["p"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.org", DstPort: 80}); err == nil {
					_ = conn.Close()
				}
			}()
			select {
			case rec := <-recCh:
				require.Equal(t, tc.chrome, velesHelloHasExtension(rec, 0xca34), "Chrome 155 trust_anchors")
				// safari sends GREASE, firefox and Go TLS do not: the global value is not used
				require.Equal(t, tc.chrome, velesHelloHasGREASE(rec), "GREASE")
			case <-ctx.Done():
				t.Fatal("no ClientHello")
			}
		})
	}
}

func velesHelloExtensions(rec []byte) (ids []uint16) {
	b := rec[5+4+2+32:]
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	b = b[2 : 2+int(binary.BigEndian.Uint16(b))]
	for len(b) >= 4 {
		ids = append(ids, binary.BigEndian.Uint16(b))
		b = b[4+int(binary.BigEndian.Uint16(b[2:])):]
	}
	return ids
}

func velesHelloHasExtension(rec []byte, id uint16) bool {
	for _, got := range velesHelloExtensions(rec) {
		if got == id {
			return true
		}
	}
	return false
}

func velesHelloHasGREASE(rec []byte) bool {
	for _, id := range velesHelloExtensions(rec) {
		if id&0x0f0f == 0x0a0a && id>>8 == id&0xff {
			return true
		}
	}
	return false
}
