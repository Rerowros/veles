package net

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/constant/features"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// P36: the batched copy (P12) is opt-in. A build without with_relay_batch
// must not batch; with relayBatch on, a copy from a decoding (non-socket)
// source into a TCP socket goes through the batch and still delivers every
// byte in order.

// The value per build tag is checked in relay_batch_tag*_veles_test.go.
func TestVelesRelayBatchFollowsTag(t *testing.T) {
	assert.Equal(t, features.WithRelayBatch, relayBatch)
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	dial, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	acc := <-accepted
	require.NotNil(t, acc)
	return dial.(*net.TCPConn), acc.(*net.TCPConn)
}

func TestVelesRelayBatchWriterFollowsSwitch(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()

	saved := relayBatch
	defer func() { relayBatch = saved }()

	relayBatch = false
	assert.Nil(t, batchWriter(a), "switch off: no batched writer even for a TCP socket")

	relayBatch = true
	if batchWriter(a) == nil {
		// with_low_memory keeps the batch off whatever the switch says
		t.Skip("low-memory build: batching stays off")
	}
}

func TestVelesRelayCopyToSocketBothModes(t *testing.T) {
	for _, on := range []bool{false, true} {
		name := "batch-off"
		if on {
			name = "batch-on"
		}
		t.Run(name, func(t *testing.T) {
			saved := relayBatch
			relayBatch = on
			defer func() { relayBatch = saved }()

			payload := make([]byte, 8<<20+321)
			_, err := rand.Read(payload)
			require.NoError(t, err)

			dst, peer := tcpPair(t)
			defer peer.Close()
			srcR, srcW := io.Pipe()

			done := make(chan error, 1)
			go func() {
				_, err := copyConn(dst, srcR)
				_ = dst.CloseWrite()
				done <- err
			}()
			// relayBatch is restored only after the copy has stopped
			copied := false
			defer func() {
				if !copied {
					_ = srcR.Close()
					_ = peer.Close()
					<-done
				}
			}()
			go func() {
				// chunked writes, like a decrypting reader handing out records
				for off := 0; off < len(payload); off += 16 << 10 {
					end := off + 16<<10
					if end > len(payload) {
						end = len(payload)
					}
					if _, err := srcW.Write(payload[off:end]); err != nil {
						break
					}
				}
				_ = srcW.Close()
			}()
			got, err := io.ReadAll(peer)
			require.NoError(t, err)
			copied = true
			require.NoError(t, <-done)
			assert.Equal(t, len(payload), len(got))
			assert.True(t, bytes.Equal(payload, got))
		})
	}
}
