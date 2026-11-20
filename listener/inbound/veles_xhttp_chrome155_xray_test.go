package inbound_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

type capturedClientHello struct {
	alpns           []string
	groups          []uint16
	keyShareGroups  []uint16
	sigAlgs         []uint16
	hasTrustAnchors bool
	hasALPS         bool
}

func parseWireClientHello(t *testing.T, rec []byte) capturedClientHello {
	t.Helper()
	require.GreaterOrEqual(t, len(rec), 9)
	require.Equal(t, byte(22), rec[0])
	require.Equal(t, byte(1), rec[5])
	msgLen := int(rec[6])<<16 | int(rec[7])<<8 | int(rec[8])
	b := rec[9 : 9+msgLen]
	b = b[2+32:] // legacy_version + random
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+extLen]

	var out capturedClientHello
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
				out.alpns = append(out.alpns, string(p[1:1+pl]))
				p = p[1+pl:]
			}
		case 0x000a: // supported_groups
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			for i := 2; i < 2+listLen; i += 2 {
				out.groups = append(out.groups, binary.BigEndian.Uint16(data[i:]))
			}
		case 0x0033: // key_share
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			p := data[2 : 2+listLen]
			for len(p) > 0 {
				g := binary.BigEndian.Uint16(p[:2])
				kl := int(binary.BigEndian.Uint16(p[2:4]))
				out.keyShareGroups = append(out.keyShareGroups, g)
				p = p[4+kl:]
			}
		case 0x000d: // signature_algorithms
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			for i := 2; i < 2+listLen; i += 2 {
				out.sigAlgs = append(out.sigAlgs, binary.BigEndian.Uint16(data[i:]))
			}
		case 0xca34:
			out.hasTrustAnchors = true
		case 17513, 17613:
			out.hasALPS = true
		}
	}
	return out
}

func containsUint16(list []uint16, target uint16) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// startClientHelloTap forwards TCP connections to upstream while capturing the
// first TLS ClientHello record seen by the proxy.
func startClientHelloTap(t *testing.T, upstream string) (string, func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var once sync.Once
	var mu sync.Mutex
	var firstHello []byte
	doneCh := make(chan struct{})

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				server, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer server.Close()

				hdr := make([]byte, 5)
				if _, err := io.ReadFull(client, hdr); err != nil {
					return
				}
				recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
				rec := make([]byte, 5+recLen)
				copy(rec, hdr)
				if _, err := io.ReadFull(client, rec[5:]); err != nil {
					return
				}
				once.Do(func() {
					mu.Lock()
					firstHello = append([]byte(nil), rec...)
					mu.Unlock()
					close(doneCh)
				})
				if _, err := server.Write(rec); err != nil {
					return
				}
				go func() { _, _ = io.Copy(server, client) }()
				_, _ = io.Copy(client, server)
			}(c)
		}
	}()

	return ln.Addr().String(), func() []byte {
		select {
		case <-doneCh:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for ClientHello")
		}
		mu.Lock()
		defer mu.Unlock()
		return firstHello
	}
}

func TestVelesXHTTPChrome155XrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)
	xrayRequiresMLKEM := velesMatrixVersionAtLeast(t, xrayVersion, 26, 9, 8)

	echoAddr := startVMessInteropEcho(t)

	t.Run("tls", func(t *testing.T) {
		cases := []struct {
			name string
			alpn []string
			mode string
		}{
			{name: "h2/packet-up", alpn: []string{"h2"}, mode: "packet-up"},
			{name: "h2/stream-up", alpn: []string{"h2"}, mode: "stream-up"},
			{name: "h2/stream-one", alpn: []string{"h2"}, mode: "stream-one"},
			// Xray splithttp/hub.go omits http.ResponseController.EnableFullDuplex(),
			// so interactive full-duplex stream-up/stream-one over HTTP/1.1 stalls
			// against Xray's net/http server (whereas packet-up uses independent POSTs).
			{name: "http1.1/packet-up", alpn: []string{"http/1.1"}, mode: "packet-up"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				xrayPort := vmessInteropReserveTCPPort(t)
				cfg := velesXHTTPXrayConfig(t, xrayPort.Port(), map[string]any{"mode": "auto"})
				velesMatrixStartXray(t, xrayBinary, cfg, xrayPort)
				xrayAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(xrayPort.Port()))

				tapAddr, getHello := startClientHelloTap(t, xrayAddr)
				host, portStr, err := net.SplitHostPort(tapAddr)
				require.NoError(t, err)
				portNum, err := net.LookupPort("tcp", portStr)
				require.NoError(t, err)

				out, err := outbound.NewVless(outbound.VlessOption{
					Name:              "xhttp_chrome155_tls",
					Server:            host,
					Port:              portNum,
					UUID:              velesMatrixUUID,
					TLS:               true,
					ServerName:        "example.com",
					SkipCertVerify:    true,
					ClientFingerprint: "chrome",
					Network:           "xhttp",
					ALPN:              tc.alpn,
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/test-xhttp",
						Host: "example.com",
						Mode: tc.mode,
					},
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = out.Close() })

				require.NoError(t, velesMatrixRoundTrip(out, echoAddr, t))

				hello := parseWireClientHello(t, getHello())
				require.True(t, hello.hasTrustAnchors, "Chrome 155 trust_anchors (0xca34) missing on %s", tc.name)
				require.True(t, containsUint16(hello.groups, 0x11ec), "X25519MLKEM768 missing in supported_groups")
				require.True(t, containsUint16(hello.keyShareGroups, 0x11ec), "X25519MLKEM768 missing in key_share")
				require.True(t, containsUint16(hello.sigAlgs, 0x0904), "ML-DSA-44 missing in signature_algorithms")
				if len(tc.alpn) == 1 && tc.alpn[0] == "http/1.1" {
					require.Equal(t, []string{"http/1.1"}, hello.alpns)
					require.False(t, hello.hasALPS, "ALPS must be stripped on http/1.1")
				} else {
					require.Equal(t, []string{"h2", "http/1.1"}, hello.alpns)
					require.True(t, hello.hasALPS, "ALPS(h2) expected on h2")
				}
			})
		}
	})

	t.Run("reality", func(t *testing.T) {
		originAddr := startTLSMirrorInteropCarrierTLS(t, func(c *tls.Config) {}).addr
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubB64 := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

		xrayPort := vmessInteropReserveTCPPort(t)
		cfgMap := map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"inbounds": []any{map[string]any{
				"listen":   "127.0.0.1",
				"port":     xrayPort.Port(),
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    []any{map[string]any{"id": velesMatrixUUID}},
					"decryption": "none",
				},
				"streamSettings": map[string]any{
					"network":  "xhttp",
					"security": "reality",
					"realitySettings": map[string]any{
						"dest":        originAddr,
						"serverNames": []string{"localhost"},
						"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
						"shortIds":    []string{velesMatrixShortID},
					},
					"xhttpSettings": map[string]any{
						"path": "/test-xhttp",
						"mode": "auto",
					},
				},
			}},
			"outbounds": []any{map[string]any{
				"protocol": "freedom",
				"settings": map[string]any{
					"finalRules": []any{map[string]any{"action": "allow"}},
				},
			}},
		}
		cfgBytes, err := json.MarshalIndent(cfgMap, "", "  ")
		require.NoError(t, err)
		velesMatrixStartXray(t, xrayBinary, cfgBytes, xrayPort)
		velesMatrixWarmUp(t, xrayPort.Port(), originAddr)
		xrayAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(xrayPort.Port()))

		for _, mode := range []string{"auto", "stream-one", "packet-up", "stream-up"} {
			t.Run("forced-mlkem/"+mode, func(t *testing.T) {
				tapAddr, getHello := startClientHelloTap(t, xrayAddr)
				host, portStr, err := net.SplitHostPort(tapAddr)
				require.NoError(t, err)
				portNum, err := net.LookupPort("tcp", portStr)
				require.NoError(t, err)

				out, err := outbound.NewVless(outbound.VlessOption{
					Name:              "xhttp_chrome155_reality",
					Server:            host,
					Port:              portNum,
					UUID:              velesMatrixUUID,
					TLS:               true,
					ServerName:        "localhost",
					ClientFingerprint: "chrome",
					Network:           "xhttp",
					RealityOpts: outbound.RealityOptions{
						PublicKey:             pubB64,
						ShortID:               velesMatrixShortID,
						SupportX25519MLKEM768: true,
					},
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/test-xhttp",
						Mode: mode,
					},
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = out.Close() })

				require.NoError(t, velesMatrixRoundTrip(out, echoAddr, t))

				hello := parseWireClientHello(t, getHello())
				require.True(t, hello.hasTrustAnchors, "Chrome 155 trust_anchors missing on REALITY XHTTP %s", mode)
				require.True(t, containsUint16(hello.groups, 0x11ec), "X25519MLKEM768 missing in supported_groups")
				require.True(t, containsUint16(hello.keyShareGroups, 0x11ec), "X25519MLKEM768 missing in key_share")
				require.True(t, containsUint16(hello.sigAlgs, 0x0904), "ML-DSA-44 missing")
			})
		}

		t.Run("adaptive-mlkem-p6", func(t *testing.T) {
			tlsC.ResetRealityMLKEMMemo()
			out, err := outbound.NewVless(outbound.VlessOption{
				Name:              "xhttp_chrome155_reality_adaptive",
				Server:            "127.0.0.1",
				Port:              xrayPort.Port(),
				UUID:              velesMatrixUUID,
				TLS:               true,
				ServerName:        "localhost",
				ClientFingerprint: "chrome",
				Network:           "xhttp",
				RealityOpts: outbound.RealityOptions{
					PublicKey: pubB64,
					ShortID:   velesMatrixShortID,
				},
				XHTTPOpts: outbound.XHTTPOptions{
					Path: "/test-xhttp",
					Mode: "packet-up",
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			if xrayRequiresMLKEM {
				// First dial strips X25519MLKEM768 (classic Chrome 155), server falls back to target.
				err = velesMatrixRoundTrip(out, echoAddr, t)
				require.Error(t, err, "expected first adaptive dial without ML-KEM to fail on Xray >= 26.9.8")
			}
			// Second dial learns X25519MLKEM768 and succeeds with Chrome 155 + ML-KEM.
			require.NoError(t, velesMatrixRoundTrip(out, echoAddr, t))
		})

		t.Run("mlkem-fingerprint-firefox-p7", func(t *testing.T) {
			out, err := outbound.NewVless(outbound.VlessOption{
				Name:              "xhttp_p7_reality",
				Server:            "127.0.0.1",
				Port:              xrayPort.Port(),
				UUID:              velesMatrixUUID,
				TLS:               true,
				ServerName:        "localhost",
				ClientFingerprint: "chrome",
				Network:           "xhttp",
				RealityOpts: outbound.RealityOptions{
					PublicKey:              pubB64,
					ShortID:                velesMatrixShortID,
					SupportX25519MLKEM768:  true,
					MLKEMClientFingerprint: "firefox",
				},
				XHTTPOpts: outbound.XHTTPOptions{
					Path: "/test-xhttp",
					Mode: "packet-up",
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })
			require.NoError(t, velesMatrixRoundTrip(out, echoAddr, t))
		})
	})
}

func TestVelesXHTTPChrome155ClientHelloWireLocal(t *testing.T) {
	// Ensures Chrome 155 + X25519MLKEM768 is tested even when XRAY_BINARY is unset.
	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)

	for _, alpn := range [][]string{{"h2"}, {"http/1.1"}} {
		name := alpn[0]
		t.Run(name, func(t *testing.T) {
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			protoCh := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				select {
				case protoCh <- tc.ConnectionState().NegotiatedProtocol:
				default:
				}
			}()

			tapAddr, getHello := startClientHelloTap(t, ln.Addr().String())
			host, portStr, err := net.SplitHostPort(tapAddr)
			require.NoError(t, err)
			portNum, err := net.LookupPort("tcp", portStr)
			require.NoError(t, err)

			out, err := outbound.NewVless(outbound.VlessOption{
				Name:              "xhttp_local_wire",
				Server:            host,
				Port:              portNum,
				UUID:              velesMatrixUUID,
				TLS:               true,
				ServerName:        "example.com",
				SkipCertVerify:    true,
				ClientFingerprint: "chrome",
				Network:           "xhttp",
				ALPN:              alpn,
				XHTTPOpts: outbound.XHTTPOptions{
					Path: "/xh",
					Host: "example.com",
					Mode: "stream-one",
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = out.DialContext(ctx, vmessInteropMetadata(t, "127.0.0.1:80"))

			hello := parseWireClientHello(t, getHello())
			require.True(t, hello.hasTrustAnchors)
			require.True(t, containsUint16(hello.groups, 0x11ec))
			require.True(t, containsUint16(hello.keyShareGroups, 0x11ec))
			require.True(t, containsUint16(hello.sigAlgs, 0x0904))
			neg := <-protoCh
			if name == "http/1.1" {
				require.Equal(t, []string{"http/1.1"}, hello.alpns)
				require.False(t, hello.hasALPS)
				require.Equal(t, "http/1.1", neg)
			} else {
				require.Equal(t, []string{"h2", "http/1.1"}, hello.alpns)
				require.True(t, hello.hasALPS)
				require.Equal(t, "h2", neg)
			}
		})
	}
}

func TestVelesXHTTPChrome155VelesH1FullDuplex(t *testing.T) {
	for _, mode := range []string{"auto", "stream-one", "stream-up", "packet-up"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			in := inbound.VlessOption{
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
				XHTTPConfig: inbound.XHTTPConfig{
					Path: "/vless-xhttp-h1",
					Host: "example.com",
					Mode: mode,
				},
			}
			out := outbound.VlessOption{
				TLS:               true,
				Fingerprint:       tlsFingerprint,
				ClientFingerprint: "chrome",
				Network:           "xhttp",
				ALPN:              []string{"http/1.1"},
				XHTTPOpts: outbound.XHTTPOptions{
					Path: "/vless-xhttp-h1",
					Host: "example.com",
					Mode: mode,
				},
			}
			testInboundVless(t, in, out)
		})
	}
}
