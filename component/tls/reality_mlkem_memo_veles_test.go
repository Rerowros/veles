package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// P6: without support-x25519mlkem768 the REALITY client
// learns per server and public key whether the server needs X25519MLKEM768.
// Based on the ClashFest core patch 0002 tests (Nemu-x, GPL-3.0).

type velesFakeAddr string

func (a velesFakeAddr) Network() string { return "tcp" }
func (a velesFakeAddr) String() string  { return string(a) }

func velesMemoConfig(t *testing.T, force bool) *RealityConfig {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &RealityConfig{PublicKey: key.PublicKey(), SupportX25519MLKEM768: force}
}

func velesMemoKey(t *testing.T, config *RealityConfig) string {
	t.Helper()
	return "203.0.113.1:443|" + string(config.PublicKey.Bytes())
}

func velesMemoEntry(key string) (realityMemoEntry, bool) {
	realityMemo.Lock()
	defer realityMemo.Unlock()
	entry, ok := realityMemo.entries[key]
	if !ok {
		return realityMemoEntry{}, false
	}
	return *entry, true
}

func velesChoose(t *testing.T, key string, config *RealityConfig) bool {
	t.Helper()
	mlkem, adaptive := realityChooseMLKEM(key, config)
	if !adaptive {
		t.Fatal("choice did not come from the memo")
	}
	return mlkem
}

func TestVelesRealityMLKEMMemoLearnsPerServer(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	config := velesMemoConfig(t, false)
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	key := addr.String() + "|" + string(config.PublicKey.Bytes())

	if mlkem, adaptive := realityChooseMLKEM(key, config); mlkem || !adaptive {
		t.Fatalf("first guess = (%v, %v), want classic and adaptive (default)", mlkem, adaptive)
	}
	realityReportMLKEM(key, false, realityOutcomeRefused, addr) // Xray >= 26.9.8 rejected the classic hello
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("memo did not flip to X25519MLKEM768 after a classic refusal")
	}
	realityReportMLKEM(key, false, realityOutcomeRefused, addr) // a stale classic attempt that was in flight
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("a stale classic refusal flipped the memo back")
	}
	realityReportMLKEM(key, true, realityOutcomeOK, addr)
	for i := 0; i < realityMemoFlipAfter-1; i++ {
		realityReportMLKEM(key, true, realityOutcomeRefused, addr) // a few refusals must not unpin a confirmed verdict
	}
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("pinned verdict was dropped by fewer refusals than realityMemoFlipAfter")
	}
	realityReportMLKEM(key, true, realityOutcomeRefused, addr)
	if mlkem, _ := realityChooseMLKEM(key, config); mlkem {
		t.Fatal("verdict did not flip after repeated refusals (server changed)")
	}

	other := addr.String() + "|" + string(velesMemoConfig(t, false).PublicKey.Bytes())
	if mlkem, _ := realityChooseMLKEM(other, config); mlkem {
		t.Fatal("memo leaked between public keys")
	}
	otherAddr := "203.0.113.2:443|" + string(config.PublicKey.Bytes())
	if mlkem, _ := realityChooseMLKEM(otherAddr, config); mlkem {
		t.Fatal("memo leaked between servers")
	}
}

func TestVelesRealityMLKEMForcedSkipsMemo(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	config := velesMemoConfig(t, true)
	if mlkem, adaptive := realityChooseMLKEM("198.51.100.1:443|x", config); !mlkem || adaptive {
		t.Fatalf("support-x25519mlkem768 = (%v, %v), want forced hybrid outside the memo", mlkem, adaptive)
	}
}

// A silent handshake (no answer from the server) neither flips an unpinned
// guess nor unpins a confirmed one. After realityMemoFlipAfter of them the next
// choice probes the other variant exactly once.
func TestVelesRealityMLKEMMemoSilentKeepsVerdict(t *testing.T) {
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	for _, tc := range []struct {
		name   string
		pinned bool
	}{{"unpinned", false}, {"pinned", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			config := velesMemoConfig(t, false)
			key := velesMemoKey(t, config)
			want := false
			if tc.pinned {
				want = true
				realityReportMLKEM(key, true, realityOutcomeOK, addr)
			} else {
				realityReportMLKEM(key, false, realityOutcomeRefused, addr) // unpinned "ML-KEM"
				realityReportMLKEM(key, true, realityOutcomeRefused, addr)  // back to unpinned classic
			}
			for i := 0; i < realityMemoFlipAfter; i++ {
				if got := velesChoose(t, key, config); got != want {
					t.Fatalf("after %d silent handshakes choice = %v, want %v", i, got, want)
				}
				realityReportMLKEM(key, want, realityOutcomeSilent, addr)
			}
			entry, _ := velesMemoEntry(key)
			if entry.mlkem != want || entry.pinned != tc.pinned || entry.failures != 0 {
				t.Fatalf("silent handshakes changed the entry: %+v", entry)
			}
			if got := velesChoose(t, key, config); got != !want {
				t.Fatalf("after %d silent handshakes choice = %v, want a single probe of %v", realityMemoFlipAfter, got, !want)
			}
			for i := 0; i < 2; i++ {
				if got := velesChoose(t, key, config); got != want {
					t.Fatalf("probe repeated: choice %d after it = %v, want %v", i, got, want)
				}
			}
		})
	}
}

// The probe's refusal or silence is a stale attempt: the pinned verdict stays.
func TestVelesRealityMLKEMMemoFailedProbeKeepsPin(t *testing.T) {
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	for _, outcome := range []realityOutcome{realityOutcomeRefused, realityOutcomeSilent} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			config := velesMemoConfig(t, false)
			key := velesMemoKey(t, config)
			realityReportMLKEM(key, true, realityOutcomeOK, addr)
			for i := 0; i < realityMemoFlipAfter; i++ {
				realityReportMLKEM(key, true, realityOutcomeSilent, addr)
			}
			if probe := velesChoose(t, key, config); probe {
				t.Fatal("no classic probe after silent handshakes")
			}
			realityReportMLKEM(key, false, outcome, addr)
			entry, _ := velesMemoEntry(key)
			if !entry.mlkem || !entry.pinned || entry.failures != 0 || entry.silent != 0 {
				t.Fatalf("failed probe changed the pinned entry: %+v", entry)
			}
			if !velesChoose(t, key, config) {
				t.Fatal("pinned ML-KEM lost after a failed probe")
			}
		})
	}
}

func TestVelesRealityMLKEMMemoProbeSuccessPins(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	config := velesMemoConfig(t, false)
	key := velesMemoKey(t, config)
	realityReportMLKEM(key, true, realityOutcomeOK, addr)
	for i := 0; i < realityMemoFlipAfter; i++ {
		realityReportMLKEM(key, true, realityOutcomeSilent, addr)
	}
	if probe := velesChoose(t, key, config); probe {
		t.Fatal("no classic probe after silent handshakes")
	}
	realityReportMLKEM(key, false, realityOutcomeOK, addr)
	if entry, _ := velesMemoEntry(key); entry.mlkem || !entry.pinned {
		t.Fatalf("successful probe was not pinned: %+v", entry)
	}
	if velesChoose(t, key, config) {
		t.Fatal("next choice after a successful classic probe is ML-KEM")
	}
}

// A silent handshake between refusals neither counts as one nor resets them.
func TestVelesRealityMLKEMMemoSilentKeepsFailures(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	config := velesMemoConfig(t, false)
	key := velesMemoKey(t, config)
	realityReportMLKEM(key, true, realityOutcomeOK, addr)
	for i := 0; i < realityMemoFlipAfter-1; i++ {
		realityReportMLKEM(key, true, realityOutcomeRefused, addr)
	}
	realityReportMLKEM(key, true, realityOutcomeSilent, addr)
	if entry, _ := velesMemoEntry(key); !entry.mlkem || !entry.pinned || entry.failures != realityMemoFlipAfter-1 {
		t.Fatalf("silent handshake touched the refusal count: %+v", entry)
	}
	realityReportMLKEM(key, true, realityOutcomeRefused, addr)
	if velesChoose(t, key, config) {
		t.Fatal("pinned verdict did not flip after realityMemoFlipAfter refusals around a silent handshake")
	}
}

func TestVelesRealityMLKEMMemoStaleSilentIgnored(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	config := velesMemoConfig(t, false)
	key := velesMemoKey(t, config)
	realityReportMLKEM(key, false, realityOutcomeRefused, addr) // now unpinned ML-KEM
	for i := 0; i < realityMemoFlipAfter+1; i++ {
		realityReportMLKEM(key, false, realityOutcomeSilent, addr) // classic attempts still in flight
	}
	if entry, _ := velesMemoEntry(key); !entry.mlkem || entry.silent != 0 {
		t.Fatalf("stale silent handshakes counted: %+v", entry)
	}
	for i := 0; i < 2; i++ {
		if !velesChoose(t, key, config) {
			t.Fatal("stale silent handshakes caused a probe")
		}
	}
}

// The very first attempt to a server that never answers creates the entry and
// counts silence the same way.
func TestVelesRealityMLKEMMemoSilentWithoutEntry(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	config := velesMemoConfig(t, false)
	key := velesMemoKey(t, config)
	for i := 0; i < realityMemoFlipAfter; i++ {
		if velesChoose(t, key, config) {
			t.Fatalf("silent attempt %d flipped to ML-KEM", i)
		}
		realityReportMLKEM(key, false, realityOutcomeSilent, addr)
	}
	if !velesChoose(t, key, config) {
		t.Fatal("no ML-KEM probe after silent first attempts")
	}
	if velesChoose(t, key, config) {
		t.Fatal("ML-KEM probe repeated")
	}
}

func TestVelesRealityClassify(t *testing.T) {
	remoteAlert := &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}
	for _, tc := range []struct {
		name     string
		err      error
		ctxErr   error
		hello    bool
		verified bool
		want     realityOutcome
	}{
		{"context deadline", errors.New("tls: use of closed connection"), context.DeadlineExceeded, true, false, realityOutcomeSilent},
		{"context canceled error", fmt.Errorf("wrapped: %w", context.Canceled), nil, true, false, realityOutcomeSilent},
		{"socket deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, nil, true, false, realityOutcomeSilent},
		{"eof", io.EOF, nil, true, false, realityOutcomeSilent},
		{"unexpected eof", io.ErrUnexpectedEOF, nil, true, false, realityOutcomeSilent},
		{"closed", &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, nil, true, false, realityOutcomeSilent},
		{"remote alert before server hello", remoteAlert, nil, false, false, realityOutcomeSilent},
		{"remote alert after server hello", remoteAlert, nil, true, false, realityOutcomeRefused},
		{"x509 after server hello", fmt.Errorf("tls: %w", x509.UnknownAuthorityError{}), nil, true, false, realityOutcomeRefused},
		{"verified then failed", io.EOF, nil, true, true, realityOutcomeNone},
		{"success", nil, nil, true, true, realityOutcomeOK},
		{"completed without authentication", nil, nil, true, false, realityOutcomeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := realityClassify(tc.err, tc.ctxErr, tc.hello, tc.verified); got != tc.want {
				t.Fatalf("realityClassify(%v, %v, hello=%v, verified=%v) = %d, want %d", tc.err, tc.ctxErr, tc.hello, tc.verified, got, tc.want)
			}
		})
	}
}

// velesReplayConn hands the already read ClientHello record to a crypto/tls
// server before the rest of the stream.
type velesReplayConn struct {
	net.Conn
	prefix []byte
}

func (c *velesReplayConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func velesSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The server sides used below; each gets the ClientHello record already read.
func velesServeClose(server net.Conn, _ []byte) { _ = server.Close() }

func velesServeSilent(server net.Conn, _ []byte) { _, _ = io.Copy(io.Discard, server) }

// velesServeSite is a plain TLS site with a self-signed certificate: what a
// REALITY server shows when it hands the hello to its target.
func velesServeSite(t *testing.T) func(net.Conn, []byte) {
	cert := velesSelfSignedCert(t)
	return func(server net.Conn, record []byte) {
		_ = tls.Server(&velesReplayConn{Conn: server, prefix: record}, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
		_ = server.Close()
	}
}

// velesListen is the server address of one test: the memo key includes it, so
// every dial of a test goes to the same listener. Loopback TCP rather than
// net.Pipe: a TLS server and a client sending its alert would block each
// other on the unbuffered pipe.
func velesListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// velesRealityDial runs one GetRealityConn to ln against serve and returns the
// ClientHello it sent, the memo key of the server and the handshake error.
func velesRealityDial(t *testing.T, ctx context.Context, ln net.Listener, id UClientHelloID, config *RealityConfig, serve func(net.Conn, []byte)) (*utls.PubClientHelloMsg, string, error) {
	t.Helper()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	result := make(chan error, 1)
	go func() {
		_, err := GetRealityConn(ctx, client, id, "example.com", config)
		result <- err
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read ClientHello header: %v", err)
	}
	record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:5])))
	copy(record, header)
	if _, err := io.ReadFull(server, record[5:]); err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	hello := utls.UnmarshalClientHello(record[5:])
	if hello == nil {
		t.Fatal("captured record is not a ClientHello")
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		serve(server, record)
	}()

	select {
	case err = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("REALITY handshake did not finish")
	}
	_ = client.Close()
	_ = server.Close()
	<-served
	return hello, realityMemoKey(client, config), err
}

// A server that drops the connection right after the ClientHello, or never
// answers until the dial context expires, has not said anything about ML-KEM:
// the memo stays as it was.
func TestVelesRealityMLKEMMemoIgnoresSilentServer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		serve   func(net.Conn, []byte)
		timeout time.Duration
	}{
		{"closed after hello", velesServeClose, 5 * time.Second},
		{"no answer until deadline", velesServeSilent, 200 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			config := velesMemoConfig(t, false)
			id, _ := GetFingerprint("chrome")
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			hello, key, err := velesRealityDial(t, ctx, velesListen(t), id, config, tc.serve)
			if err == nil {
				t.Fatal("handshake succeeded")
			}
			t.Logf("handshake error: %v", err)
			if slices.Contains(keyShareGroups(hello), utls.X25519MLKEM768) {
				t.Fatalf("first ClientHello has X25519MLKEM768: %v", keyShareGroups(hello))
			}
			if entry, _ := velesMemoEntry(key); entry.mlkem || entry.failures != 0 {
				t.Fatalf("silent server changed the memo: %+v", entry)
			}
			if velesChoose(t, key, config) {
				t.Fatal("next attempt after a silent server uses ML-KEM")
			}
		})
	}
}

// A learned "needs ML-KEM" verdict must reach the wire. The first attempt is
// classic and is refused by a plain TLS site (what Xray >= 26.9.8 does with a
// classic hello: it hands it to the target). For a fingerprint with the share
// (firefox) the next hello keeps it; for one without it (edge, and chrome120,
// which shares the Client name with chrome) the hello is swapped for chrome,
// the only one that can pass such a server.
func TestVelesRealityMLKEMMemoReachesClientHello(t *testing.T) {
	for _, name := range []string{"firefox", "edge", "chrome120"} {
		t.Run(name, func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			id, _ := GetFingerprint(name)
			config := velesMemoConfig(t, false)
			ln := velesListen(t)

			hello, key, err := velesRealityDial(t, context.Background(), ln, id, config, velesServeSite(t))
			if err == nil {
				t.Fatal("handshake with a plain TLS site succeeded")
			}
			t.Logf("refused: %v", err)
			if slices.Contains(keyShareGroups(hello), utls.X25519MLKEM768) {
				t.Fatalf("first ClientHello has X25519MLKEM768: %v", keyShareGroups(hello))
			}
			if entry, _ := velesMemoEntry(key); !entry.mlkem || entry.pinned {
				t.Fatalf("refusal did not flip the memo to unpinned ML-KEM: %+v", entry)
			}
			hello, _, _ = velesRealityDial(t, context.Background(), ln, id, config, velesServeClose)
			t.Logf("%s second ClientHello: %d bytes, key shares %v", name, len(hello.Raw), keyShareGroups(hello))
			if !xrayAcceptsKeyShares(hello.KeyShares) {
				t.Fatalf("second ClientHello lacks X25519MLKEM768 before X25519: %v", keyShareGroups(hello))
			}
		})
	}
}

// A success or a refusal starts the count of silent handshakes over: rare
// timeouts on a working server must never add up to a probe.
func TestVelesRealityMLKEMMemoSilentCountResets(t *testing.T) {
	addr := net.Addr(velesFakeAddr("203.0.113.1:443"))
	for name, between := range map[string]realityOutcome{"ok": realityOutcomeOK, "refused": realityOutcomeRefused} {
		t.Run(name, func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			config := velesMemoConfig(t, false)
			key := velesMemoKey(t, config)
			realityReportMLKEM(key, true, realityOutcomeOK, addr)
			for round := 0; round < 3; round++ {
				for i := 0; i < realityMemoFlipAfter-1; i++ {
					realityReportMLKEM(key, true, realityOutcomeSilent, addr)
				}
				if !velesChoose(t, key, config) {
					t.Fatalf("round %d: silent handshakes separated by an answer added up to a probe", round)
				}
				realityReportMLKEM(key, true, between, addr)
				if between == realityOutcomeRefused {
					break // a second refusal would be counted towards the flip
				}
			}
			for i := 0; i < realityMemoFlipAfter-1; i++ {
				realityReportMLKEM(key, true, realityOutcomeSilent, addr)
			}
			if !velesChoose(t, key, config) {
				t.Fatal("silent handshakes before and after an answer added up to a probe")
			}
		})
	}
}
