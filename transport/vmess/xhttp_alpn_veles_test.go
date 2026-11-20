package vmess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func testGenerateSelfSignedCert(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func testParseClientHelloExtensions(t *testing.T, record []byte) (alpns []string, groups []uint16, hasTrustAnchors bool, hasALPS bool) {
	t.Helper()
	if len(record) < 9 || record[0] != 22 || record[5] != 1 {
		t.Fatalf("unexpected TLS record header: %x", record)
	}
	msgLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	b := record[9 : 9+msgLen]
	b = b[2+32:] // version + random
	sidLen := int(b[0])
	b = b[1+sidLen:]
	csLen := int(binary.BigEndian.Uint16(b))
	b = b[2+csLen:]
	compLen := int(b[0])
	b = b[1+compLen:]
	extTotal := int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+extTotal]
	for len(b) > 0 {
		id := binary.BigEndian.Uint16(b[:2])
		l := int(binary.BigEndian.Uint16(b[2:4]))
		data := b[4 : 4+l]
		b = b[4+l:]
		switch id {
		case 0x0010: // ALPN
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			p := data[2 : 2+listLen]
			for len(p) > 0 {
				pl := int(p[0])
				alpns = append(alpns, string(p[1:1+pl]))
				p = p[1+pl:]
			}
		case 0x000a: // supported_groups
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			for i := 2; i < 2+listLen; i += 2 {
				groups = append(groups, binary.BigEndian.Uint16(data[i:]))
			}
		case 0xca34: // trust_anchors (Chrome 155)
			hasTrustAnchors = true
		case 17513, 17613:
			hasALPS = true
		}
	}
	return alpns, groups, hasTrustAnchors, hasALPS
}

func TestVelesStreamTLSConnChrome155ALPN(t *testing.T) {
	cert := testGenerateSelfSignedCert(t, "example.com")
	cases := []struct {
		name      string
		nextProto []string
		wantALPNs []string
		wantProto string
		wantALPS  bool
	}{
		{
			name:      "http1.1-only",
			nextProto: []string{"http/1.1"},
			wantALPNs: []string{"http/1.1"},
			wantProto: "http/1.1",
			wantALPS:  false,
		},
		{
			name:      "h2-default-chrome155",
			nextProto: []string{"h2"},
			wantALPNs: []string{"h2", "http/1.1"},
			wantProto: "h2",
			wantALPS:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientPipe, serverPipe := net.Pipe()
			defer clientPipe.Close()
			defer serverPipe.Close()
			_ = clientPipe.SetDeadline(time.Now().Add(5 * time.Second))
			_ = serverPipe.SetDeadline(time.Now().Add(5 * time.Second))

			type serverRes struct {
				proto           string
				alpns           []string
				hasMLKEM        bool
				hasTrustAnchors bool
				hasALPS         bool
				err             error
			}
			resCh := make(chan serverRes, 1)
			go func() {
				var r serverRes
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(serverPipe, hdr); err != nil {
					r.err = err
					resCh <- r
					return
				}
				recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
				rec := make([]byte, 5+recLen)
				copy(rec, hdr)
				if _, err := io.ReadFull(serverPipe, rec[5:]); err != nil {
					r.err = err
					resCh <- r
					return
				}
				var groups []uint16
				r.alpns, groups, r.hasTrustAnchors, r.hasALPS = testParseClientHelloExtensions(t, rec)
				for _, g := range groups {
					if g == 0x11ec {
						r.hasMLKEM = true
					}
				}
				replay := &prefixConn{Conn: serverPipe, prefix: rec}
				srv := tls.Server(replay, &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1"},
				})
				r.err = srv.Handshake()
				r.proto = srv.ConnectionState().NegotiatedProtocol
				_ = serverPipe.Close()
				resCh <- r
			}()

			conn, err := StreamTLSConn(context.Background(), clientPipe, &TLSConfig{
				Host:              "example.com",
				SkipCertVerify:    true,
				ClientFingerprint: "chrome",
				NextProtos:        tc.nextProto,
			})
			_ = clientPipe.Close()
			if conn != nil {
				_ = conn.Close()
			}
			sr := <-resCh
			if err != nil {
				t.Fatalf("StreamTLSConn failed: %v", err)
			}
			if sr.err != nil {
				t.Fatalf("server handshake failed: %v", sr.err)
			}
			if !sr.hasTrustAnchors || !sr.hasMLKEM {
				t.Fatalf("expected Chrome 155 + X25519MLKEM768, got trustAnchors=%v mlkem=%v", sr.hasTrustAnchors, sr.hasMLKEM)
			}
			if sr.hasALPS != tc.wantALPS {
				t.Fatalf("hasALPS = %v, want %v (alpns=%v)", sr.hasALPS, tc.wantALPS, sr.alpns)
			}
			if len(sr.alpns) != len(tc.wantALPNs) {
				t.Fatalf("client ALPNs = %v, want %v", sr.alpns, tc.wantALPNs)
			}
			for i := range tc.wantALPNs {
				if sr.alpns[i] != tc.wantALPNs[i] {
					t.Fatalf("client ALPNs = %v, want %v", sr.alpns, tc.wantALPNs)
				}
			}
			if sr.proto != tc.wantProto {
				t.Fatalf("server negotiated %q, want %q", sr.proto, tc.wantProto)
			}
		})
	}
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
