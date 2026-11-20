package outbound

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fragment"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// firstTLSRecordLen starts a raw TCP listener and returns its address and a
// channel with the length of the first TLS record the client sends.
func firstTLSRecordLen(t *testing.T) (netip.AddrPort, <-chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	result := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil || header[0] != 22 {
			result <- -1
			return
		}
		result <- int(binary.BigEndian.Uint16(header[3:5]))
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), result
}

// sendClientHello dials through dial and starts a TLS handshake (it never
// completes: the listener only reads the first record header).
func sendClientHello(t *testing.T, dial func(context.Context, *C.Metadata) (net.Conn, error), addr netip.AddrPort) {
	t.Helper()
	conn, err := dial(context.Background(), &C.Metadata{NetWork: C.TCP, DstIP: addr.Addr(), DstPort: addr.Port()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _ = tls.Client(conn, &tls.Config{ServerName: "example.com"}).Handshake() }()
}

// P31: fragment-opts on type direct splits the first TLS ClientHello, also when
// the direct proxy is used as a dialer-proxy; without it the record is whole.
func TestVelesDirectFragmentOpts(t *testing.T) {
	fragmented := NewDirectWithOption(DirectOption{
		BasicOption: BasicOption{FragmentOpts: fragment.Options{Packets: "tlshello", Length: "10-20", Delay: "0"}},
		Name:        "direct-fragment",
	})
	plain := NewDirectWithOption(DirectOption{Name: "direct-plain"})
	asDialerProxy := func(d *Direct) func(context.Context, *C.Metadata) (net.Conn, error) {
		return func(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
			return proxydialer.New(d, false).DialContext(ctx, "tcp", metadata.RemoteAddress())
		}
	}
	direct := func(d *Direct) func(context.Context, *C.Metadata) (net.Conn, error) {
		return func(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
			return d.DialContext(ctx, metadata)
		}
	}

	for _, tc := range []struct {
		name  string
		dial  func(context.Context, *C.Metadata) (net.Conn, error)
		split bool
	}{
		{"direct with fragment-opts", direct(fragmented), true},
		{"dialer-proxy direct with fragment-opts", asDialerProxy(fragmented), true},
		{"direct without fragment-opts", direct(plain), false},
		{"dialer-proxy direct without fragment-opts", asDialerProxy(plain), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, recordLen := firstTLSRecordLen(t)
			sendClientHello(t, tc.dial, addr)
			got := <-recordLen
			require.Positive(t, got, "no TLS record received")
			if tc.split {
				require.LessOrEqual(t, got, 20, "first ClientHello record must be split")
			} else {
				require.Greater(t, got, 100, "ClientHello must stay one record")
			}
		})
	}
}
