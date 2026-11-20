package vmess

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"

	mtls "github.com/metacubex/tls"
)

// velesHello is what a server sees in the first ClientHello of a dial.
type velesHello struct {
	exts  []uint16
	alpns []string
	alps  bool
}

func (h velesHello) has(id uint16) bool { return slices.Contains(h.exts, id) }

// chrome155 has GREASE and trust_anchors (0xca34, P20).
func (h velesHello) isChrome155() bool { return h.hasGREASE() && h.has(0xca34) }

// firefox has record_size_limit (0x001c) and no GREASE.
func (h velesHello) isFirefox() bool { return h.has(0x001c) && !h.hasGREASE() }

// Go crypto/tls sends neither GREASE, trust_anchors nor record_size_limit.
func (h velesHello) isGoTLS() bool { return !h.hasGREASE() && !h.has(0xca34) && !h.has(0x001c) }

func (h velesHello) hasGREASE() bool {
	for _, id := range h.exts {
		if id&0x0f0f == 0x0a0a && id>>8 == id&0xff {
			return true
		}
	}
	return false
}

func velesParseHello(t *testing.T, record []byte) velesHello {
	t.Helper()
	var h velesHello
	h.alpns, _, _, h.alps = testParseClientHelloExtensions(t, record)
	b := record[9:]
	b = b[2+32:]
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	b = b[2 : 2+int(binary.BigEndian.Uint16(b))]
	for len(b) > 0 {
		h.exts = append(h.exts, binary.BigEndian.Uint16(b))
		b = b[4+int(binary.BigEndian.Uint16(b[2:])):]
	}
	return h
}

// velesCaptureHello runs dial against one end of a pipe and returns the first
// TLS record written to it; the server then hangs up, so dial fails.
func velesCaptureHello(t *testing.T, dial func(conn net.Conn) error) (velesHello, error) {
	t.Helper()
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	recCh := make(chan []byte, 1)
	go func() {
		defer server.Close()
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(server, hdr); err != nil {
			recCh <- nil
			return
		}
		rec := make([]byte, 5+int(binary.BigEndian.Uint16(hdr[3:5])))
		copy(rec, hdr)
		if _, err := io.ReadFull(server, rec[5:]); err != nil {
			recCh <- nil
			return
		}
		recCh <- rec
	}()
	err := dial(client)
	_ = client.Close()
	rec := <-recCh
	if rec == nil {
		t.Fatalf("no ClientHello, dial error: %v", err)
	}
	return velesParseHello(t, rec), err
}

func velesStreamTLSHello(t *testing.T, cfg *TLSConfig) (velesHello, error) {
	t.Helper()
	return velesCaptureHello(t, func(conn net.Conn) error {
		c, err := StreamTLSConn(context.Background(), conn, cfg)
		if c != nil {
			_ = c.Close()
		}
		return err
	})
}

// P29: plain TLS (vless/vmess/trojan raw TLS, gRPC, XHTTP, AnyTLS, ...) uses
// StreamTLSConn; without client-fingerprint it sends the Chrome 155 hello and
// the ALPN of the preset, as Xray does.
func TestVelesStreamTLSConnDefaultFingerprint(t *testing.T) {
	cases := []struct {
		name        string
		fingerprint string
		nextProtos  []string
		want        func(velesHello) bool
		wantALPNs   []string
		wantALPS    bool
	}{
		{"empty", "", nil, velesHello.isChrome155, []string{"h2", "http/1.1"}, true},
		{"empty-grpc-h2", "", []string{"h2"}, velesHello.isChrome155, []string{"h2", "http/1.1"}, true},
		{"empty-http1.1-only-P27", "", []string{"http/1.1"}, velesHello.isChrome155, []string{"http/1.1"}, false},
		{"Chrome", "Chrome", nil, velesHello.isChrome155, []string{"h2", "http/1.1"}, true},
		{"spaces", " chrome ", nil, velesHello.isChrome155, []string{"h2", "http/1.1"}, true},
		{"typo", "chrom", nil, velesHello.isChrome155, []string{"h2", "http/1.1"}, true},
		{"explicit-firefox", "firefox", nil, velesHello.isFirefox, []string{"h2", "http/1.1"}, false},
		{"none", "none", nil, velesHello.isGoTLS, nil, false},
		{"none-alpn", "None", []string{"h2"}, velesHello.isGoTLS, []string{"h2"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hello, _ := velesStreamTLSHello(t, &TLSConfig{
				Host:              "example.com",
				SkipCertVerify:    true,
				ClientFingerprint: tc.fingerprint,
				NextProtos:        tc.nextProtos,
			})
			if !tc.want(hello) {
				t.Fatalf("unexpected hello for client-fingerprint %q: extensions %x", tc.fingerprint, hello.exts)
			}
			if !slices.Equal(hello.alpns, tc.wantALPNs) {
				t.Fatalf("ALPN = %v, want %v", hello.alpns, tc.wantALPNs)
			}
			if hello.alps != tc.wantALPS {
				t.Fatalf("ALPS = %v, want %v", hello.alps, tc.wantALPS)
			}
		})
	}
}

// P29: REALITY with an empty, unknown or differently cased client-fingerprint
// uses chrome instead of failing with "please set a client-fingerprint";
// explicit "none" stays an error (TestStreamTLSConnRejectsExplicitNoneRealityFingerprint).
func TestVelesStreamTLSConnRealityFingerprintFallback(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "chrom", " CHROME "} {
		t.Run(name, func(t *testing.T) {
			hello, err := velesStreamTLSHello(t, &TLSConfig{
				Host:              "example.com",
				ClientFingerprint: name,
				Reality:           &tlsC.RealityConfig{PublicKey: key.PublicKey(), SupportX25519MLKEM768: true},
			})
			if err != nil && strings.Contains(err.Error(), "please set") {
				t.Fatalf("REALITY error: %v", err)
			}
			if !hello.isChrome155() {
				t.Fatalf("REALITY hello is not chrome: extensions %x", hello.exts)
			}
		})
	}
}

// P29: WebSocket over TLS builds its TLS itself; same default, P24 keeps
// ALPN http/1.1 without ALPS.
func TestVelesWebsocketTLSDefaultFingerprint(t *testing.T) {
	cases := []struct {
		fingerprint string
		want        func(velesHello) bool
	}{
		{"", velesHello.isChrome155},
		{"Chrome ", velesHello.isChrome155},
		{"chrom", velesHello.isChrome155},
		{"none", velesHello.isGoTLS},
	}
	for _, tc := range cases {
		t.Run(tc.fingerprint, func(t *testing.T) {
			hello, _ := velesCaptureHello(t, func(conn net.Conn) error {
				c, err := StreamWebsocketConn(context.Background(), conn, &WebsocketConfig{
					Host:              "example.com",
					Port:              "443",
					Path:              "/",
					TLS:               true,
					TLSConfig:         &mtls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
					ClientFingerprint: tc.fingerprint,
				})
				if c != nil {
					_ = c.Close()
				}
				return err
			})
			if !tc.want(hello) {
				t.Fatalf("unexpected hello for client-fingerprint %q: extensions %x", tc.fingerprint, hello.exts)
			}
			if !slices.Equal(hello.alpns, []string{"http/1.1"}) || hello.alps {
				t.Fatalf("ALPN = %v, ALPS = %v; want [http/1.1] without ALPS", hello.alpns, hello.alps)
			}
		})
	}
}
