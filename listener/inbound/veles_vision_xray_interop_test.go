package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// P30: Vision pads records of 900 bytes and more (inner ClientHello with
// ML-KEM, ServerHello, certificates) with 0..255 random bytes like Xray. A real
// Xray REALITY+Vision server must accept that, and Veles must read Xray's
// padding of large records: a 1 MiB download over inner TLS 1.3 through Xray.
func TestVelesVisionXrayInteropLargeTLSRecords(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at a current Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	supportX25519MLKEM768 := velesMatrixVersionAtLeast(t, strings.Fields(string(versionOutput))[1], 26, 9, 8)

	const downloadSize = 1 << 20
	payload := make([]byte, downloadSize)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	innerAddr := startVelesVisionInnerTLSServer(t, payload)

	origin := startTLSMirrorInteropCarrierTLS(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	startXrayRealityServer(t, xrayBinary, xrayRealityServerConfig(t, xrayPort.Port(), origin.addr, privateKey), xrayPort)

	out, err := outbound.NewVless(outbound.VlessOption{
		Name:              "vless_vision_xray",
		Server:            "127.0.0.1",
		Port:              xrayPort.Port(),
		UUID:              xrayRealityVisionUUID,
		Flow:              "xtls-rprx-vision",
		TLS:               true,
		ServerName:        "localhost",
		ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{
			PublicKey:             base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
			ShortID:               xrayRealityShortID,
			SupportX25519MLKEM768: supportX25519MLKEM768,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	for round := 0; round < 3; round++ {
		conn, err := out.DialContext(context.Background(), vmessInteropMetadata(t, innerAddr))
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
		recorder := &velesFirstWriteRecorder{Conn: conn}
		// Chrome's ClientHello carries an ML-KEM key share (~1.8 KB); the
		// stdlib client has ML-KEM off under this module's go 1.20 GODEBUG.
		inner := utls.UClient(recorder, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		require.NoError(t, inner.Handshake(), "round %d", round)
		require.Greater(t, recorder.firstWrite(), 900, "inner ClientHello must be a large record")
		_, err = inner.Write([]byte("GET\n"))
		require.NoError(t, err)
		got := make([]byte, downloadSize)
		_, err = io.ReadFull(inner, got)
		require.NoError(t, err, "round %d", round)
		require.Equal(t, sha256.Sum256(payload), sha256.Sum256(got), "round %d", round)
		_ = inner.Close()
	}
}

type velesFirstWriteRecorder struct {
	net.Conn
	once sync.Once
	mu   sync.Mutex
	size int
}

func (c *velesFirstWriteRecorder) Write(p []byte) (int, error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.size = len(p)
		c.mu.Unlock()
	})
	return c.Conn.Write(p)
}

func (c *velesFirstWriteRecorder) firstWrite() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}

// startVelesVisionInnerTLSServer serves payload over TLS 1.3 with an RSA
// certificate after one request line.
func startVelesVisionInnerTLSServer(t *testing.T, payload []byte) string {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeRSA)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line := make([]byte, 4)
				if _, err := io.ReadFull(conn, line); err != nil || !bytes.Equal(line, []byte("GET\n")) {
					return
				}
				_, _ = conn.Write(payload)
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}
