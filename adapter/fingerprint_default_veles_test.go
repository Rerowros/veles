package adapter

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// velesCaptureProxyHello starts a TCP server that keeps the first TLS record
// of the first connection, parses mapping as a proxy pointed at it and dials
// through the proxy. The server hangs up after the record, so the dial fails.
func velesCaptureProxyHello(t *testing.T, mapping map[string]any) []byte {
	t.Helper()
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

	mapping["server"] = "127.0.0.1"
	mapping["port"] = ln.Addr().(*net.TCPAddr).Port
	proxy, err := ParseProxy(mapping)
	require.NoError(t, err)
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.org", DstPort: 80})
		if err == nil {
			// gRPC and XHTTP send the request (and dial) on first write
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	select {
	case rec := <-recCh:
		require.Equal(t, byte(22), rec[0], "not a TLS handshake record")
		return rec
	case <-ctx.Done():
		t.Fatal("no ClientHello")
		return nil
	}
}

// trust_anchors (0xca34) is sent only by the Chrome 155 hello (P20).
func velesHelloIsChrome155(rec []byte) bool {
	b := rec[5+4+2+32:]                       // record header, handshake header, version, random
	b = b[1+int(b[0]):]                       // session id
	b = b[2+int(binary.BigEndian.Uint16(b)):] // cipher suites
	b = b[1+int(b[0]):]                       // compression methods
	b = b[2 : 2+int(binary.BigEndian.Uint16(b))]
	for len(b) >= 4 {
		if binary.BigEndian.Uint16(b) == 0xca34 {
			return true
		}
		b = b[4+int(binary.BigEndian.Uint16(b[2:])):]
	}
	return false
}

// P29: every plain-TLS transport of vless, vmess and trojan sends the Chrome
// hello without client-fingerprint; "none" keeps Go crypto/tls; an explicit
// value on the proxy wins.
func TestVelesProxyTLSDefaultsToChrome(t *testing.T) {
	transports := map[string]map[string]any{
		"tcp":   {},
		"ws":    {"network": "ws", "ws-opts": map[string]any{"path": "/"}},
		"grpc":  {"network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "x"}},
		"xhttp": {"network": "xhttp", "xhttp-opts": map[string]any{"path": "/", "mode": "packet-up"}},
	}
	protocols := map[string]map[string]any{
		"vless":  {"type": "vless", "uuid": "11111111-2222-3333-4444-555555555555", "tls": true, "servername": "example.com"},
		"vmess":  {"type": "vmess", "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0, "cipher": "auto", "tls": true, "servername": "example.com"},
		"trojan": {"type": "trojan", "password": "p", "sni": "example.com"},
	}
	for protoName, proto := range protocols {
		for transportName, transport := range transports {
			if protoName != "vless" && transportName == "xhttp" {
				continue // XHTTP is vless-only
			}
			for _, tc := range []struct {
				fingerprint any
				chrome      bool
			}{
				{nil, true},
				{"Chrome", true},
				{"chrom", true},
				{"none", false},
				{"firefox", false},
			} {
				name := protoName + "/" + transportName + "/" + func() string {
					if tc.fingerprint == nil {
						return "unset"
					}
					return tc.fingerprint.(string)
				}()
				t.Run(name, func(t *testing.T) {
					mapping := map[string]any{"name": "p29", "skip-cert-verify": true}
					for k, v := range proto {
						mapping[k] = v
					}
					for k, v := range transport {
						mapping[k] = v
					}
					if tc.fingerprint != nil {
						mapping["client-fingerprint"] = tc.fingerprint
					}
					rec := velesCaptureProxyHello(t, mapping)
					require.Equal(t, tc.chrome, velesHelloIsChrome155(rec), "Chrome 155 hello")
				})
			}
		}
	}
}
