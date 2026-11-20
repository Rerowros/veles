package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

const (
	extALPN     = 16
	extALPSOld  = 17513 // draft-vvv-tls-alps-01 (0x4469)
	extALPSNew  = 17613 // draft-ietf-tls-alps-00 (0x44cd)
)

func parseALPNProtocols(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("alpn data too short: %d", len(data))
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	b := data[2:]
	if len(b) != listLen {
		return nil, fmt.Errorf("alpn length mismatch: listLen=%d, remaining=%d", listLen, len(b))
	}
	var protos []string
	for len(b) > 0 {
		protoLen := int(b[0])
		b = b[1:]
		if len(b) < protoLen {
			return nil, fmt.Errorf("alpn proto truncated: need %d, have %d", protoLen, len(b))
		}
		protos = append(protos, string(b[:protoLen]))
		b = b[protoLen:]
	}
	return protos, nil
}

// generateTestCertificate creates an in-memory self-signed certificate for serverName.
func generateTestCertificate(t *testing.T, serverName string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// TestVelesWebsocketHandshakeStripsALPS verifies P24:
// When building websocket handshake state (which forces ALPN = ["http/1.1"]),
// ALPS extensions (17513 and 17613) must be completely removed from both
// UConn.Extensions and the serialized ClientHello.
func TestVelesWebsocketHandshakeStripsALPS(t *testing.T) {
	fps := []string{
		"chrome",
		"chrome155",
		"chrome133",
		"chrome120",
		"firefox",
		"safari",
		"edge",
	}

	for _, fpName := range fps {
		t.Run(fpName, func(t *testing.T) {
			id, ok := GetFingerprint(fpName)
			if !ok {
				t.Fatalf("fingerprint %q not found", fpName)
			}

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			uClient := UClient(clientConn, &utls.Config{
				ServerName: "example.com",
			}, id)

			err := BuildWebsocketHandshakeState(uClient)
			if err != nil {
				t.Fatalf("BuildWebsocketHandshakeState failed: %v", err)
			}

			// 1. Verify in-memory UConn.Extensions has NO ALPS extension instances
			for _, ext := range uClient.Extensions {
				switch ext.(type) {
				case *utls.ApplicationSettingsExtension:
					t.Fatalf("found *utls.ApplicationSettingsExtension in uClient.Extensions for %s", fpName)
				case *utls.ApplicationSettingsExtensionNew:
					t.Fatalf("found *utls.ApplicationSettingsExtensionNew in uClient.Extensions for %s", fpName)
				}
			}

			// 2. Parse serialized ClientHello wire bytes
			rawHello := uClient.HandshakeState.Hello.Raw
			if len(rawHello) == 0 {
				t.Fatal("empty serialized ClientHello")
			}
			hello := parseClientHello(t, rawHello)

			// 3. Confirm ALPN extension exists and contains ONLY ["http/1.1"]
			alpnData, hasALPN := hello.extensions[extALPN]
			if !hasALPN {
				t.Fatalf("expected ALPN extension (16) in ClientHello for %s", fpName)
			}
			protos, err := parseALPNProtocols(alpnData)
			if err != nil {
				t.Fatalf("failed to parse ALPN data: %v", err)
			}
			if !slices.Equal(protos, []string{"http/1.1"}) {
				t.Fatalf("unexpected ALPN protocols for %s: got %v, want [http/1.1]", fpName, protos)
			}

			// 4. Assert NO ALPS extension in the serialized extension IDs or map
			if slices.Contains(hello.extensionIDs, extALPSOld) {
				t.Fatalf("found ALPS extension 17513 in ClientHello extensionIDs for %s", fpName)
			}
			if slices.Contains(hello.extensionIDs, extALPSNew) {
				t.Fatalf("found ALPS extension 17613 in ClientHello extensionIDs for %s", fpName)
			}
			if _, ok := hello.extensions[extALPSOld]; ok {
				t.Fatalf("found ALPS extension 17513 in ClientHello extensions map for %s", fpName)
			}
			if _, ok := hello.extensions[extALPSNew]; ok {
				t.Fatalf("found ALPS extension 17613 in ClientHello extensions map for %s", fpName)
			}
		})
	}
}

// TestVelesWebsocketTLSHandshakeSuccess tests that a full TLS handshake succeeds
// with ALPN negotiating http/1.1 when BuildWebsocketHandshakeState is used.
func TestVelesWebsocketTLSHandshakeSuccess(t *testing.T) {
	cert := generateTestCertificate(t, "example.com")
	fps := []string{"chrome", "chrome155", "chrome133", "firefox", "safari"}

	for _, fpName := range fps {
		t.Run(fpName, func(t *testing.T) {
			id, ok := GetFingerprint(fpName)
			if !ok {
				t.Fatalf("fingerprint %q not found", fpName)
			}

			clientPipe, serverPipe := net.Pipe()
			t.Cleanup(func() {
				clientPipe.Close()
				serverPipe.Close()
			})

			serverTLS := tls.Server(serverPipe, &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"http/1.1"},
			})

			uClient := UClient(clientPipe, &utls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
			}, id)

			err := BuildWebsocketHandshakeState(uClient)
			if err != nil {
				t.Fatalf("BuildWebsocketHandshakeState: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			serverErrCh := make(chan error, 1)
			go func() {
				serverErrCh <- serverTLS.HandshakeContext(ctx)
			}()

			clientErr := uClient.HandshakeContext(ctx)
			serverErr := <-serverErrCh

			if clientErr != nil {
				t.Fatalf("client handshake failed: %v", clientErr)
			}
			if serverErr != nil {
				t.Fatalf("server handshake failed: %v", serverErr)
			}

			if negotiated := serverTLS.ConnectionState().NegotiatedProtocol; negotiated != "http/1.1" {
				t.Fatalf("negotiated proto %q, want http/1.1", negotiated)
			}
		})
	}
}
