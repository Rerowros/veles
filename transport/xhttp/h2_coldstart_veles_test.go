package xhttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

// TestVelesH2TransportColdStartMaxConnsPerHost verifies P25:
// In NewTransport (HTTP/2 branch), MaxConnsPerHost must be set to 1 so that
// a burst of concurrent requests during cold start (before the first connection
// finishes dialing and handshake) opens strictly 1 physical TCP connection,
// while HTTP/1.1 remains unrestricted to preserve packet-up parallel uploads.
func TestVelesH2TransportColdStartMaxConnsPerHost(t *testing.T) {
	// Start an HTTP server supporting both unencrypted HTTP/2 and HTTP/1.1.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small delay to simulate processing so requests overlap
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: handler, Protocols: protocols}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	serverAddr := ln.Addr().String()

	t.Run("H2_ColdStartBurst_SingleDial", func(t *testing.T) {
		var dialCount atomic.Int64

		dialRaw := func(ctx context.Context) (net.Conn, error) {
			dialCount.Add(1)
			// Simulate network latency / handshake time during cold start
			time.Sleep(50 * time.Millisecond)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		}

		wrapTLS := func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) {
			return conn, nil
		}

		tr := NewTransport(dialRaw, wrapTLS, nil, []string{"h2"}, 0)
		t.Cleanup(func() {
			if closer, ok := tr.(io.Closer); ok {
				_ = closer.Close()
			}
		})

		const burst = 5
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		errs := make([]error, burst)

		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startGate
				req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/test", serverAddr), nil)
				if err != nil {
					errs[idx] = err
					return
				}
				resp, err := tr.RoundTrip(req)
				if err != nil {
					errs[idx] = err
					return
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}(i)
		}

		// Release all requests at the exact same instant
		close(startGate)
		wg.Wait()

		for i, err := range errs {
			require.NoError(t, err, "request %d failed", i)
		}

		dials := dialCount.Load()
		if dials != 1 {
			t.Fatalf("expected strictly 1 dial for H2 transport slot during cold-start burst, got %d", dials)
		}
	})

	t.Run("H2_ReuseManager_ColdStartBurst_SingleDial", func(t *testing.T) {
		var dialCount atomic.Int64

		dialRaw := func(ctx context.Context) (net.Conn, error) {
			dialCount.Add(1)
			time.Sleep(50 * time.Millisecond)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		}

		wrapTLS := func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) {
			return conn, nil
		}

		makeTransport := func() http.RoundTripper {
			return NewTransport(dialRaw, wrapTLS, nil, []string{"h2"}, 0)
		}

		manager, err := NewReuseManager(&ReuseConfig{
			MaxConcurrency: "16",
			MaxConnections: "1",
		}, makeTransport)
		require.NoError(t, err)
		t.Cleanup(func() { _ = manager.Close() })

		const burst = 5
		var wg sync.WaitGroup
		startGate := make(chan struct{})
		errs := make([]error, burst)

		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startGate
				rt := manager.GetTransport()
				defer func() {
					if closer, ok := rt.(io.Closer); ok {
						_ = closer.Close()
					}
				}()
				req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/test", serverAddr), nil)
				if err != nil {
					errs[idx] = err
					return
				}
				resp, err := rt.RoundTrip(req)
				if err != nil {
					errs[idx] = err
					return
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}(i)
		}

		close(startGate)
		wg.Wait()

		for i, err := range errs {
			require.NoError(t, err, "request %d failed", i)
		}

		dials := dialCount.Load()
		if dials != 1 {
			t.Fatalf("expected strictly 1 dial via ReuseManager during cold-start burst, got %d", dials)
		}
	})

	t.Run("H1_PreservesMultipleConnsForParallelUploads", func(t *testing.T) {
		var dialCount atomic.Int64

		dialRaw := func(ctx context.Context) (net.Conn, error) {
			dialCount.Add(1)
			time.Sleep(50 * time.Millisecond)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		}

		wrapTLS := func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) {
			return conn, nil
		}

		// http/1.1 branch
		tr := NewTransport(dialRaw, wrapTLS, nil, []string{"http/1.1"}, 0)
		t.Cleanup(func() {
			if closer, ok := tr.(io.Closer); ok {
				_ = closer.Close()
			}
		})

		const burst = 4
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		errs := make([]error, burst)

		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startGate
				req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/test", serverAddr), nil)
				if err != nil {
					errs[idx] = err
					return
				}
				resp, err := tr.RoundTrip(req)
				if err != nil {
					errs[idx] = err
					return
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}(i)
		}

		close(startGate)
		wg.Wait()

		for i, err := range errs {
			require.NoError(t, err, "request %d failed", i)
		}

		dials := dialCount.Load()
		// In HTTP/1.1, concurrent requests cannot be multiplexed over a single connection,
		// so multiple connections MUST be dialed.
		if dials <= 1 {
			t.Fatalf("expected >1 dials for HTTP/1.1 concurrent requests (packet-up parallelism), got %d", dials)
		}
	})
}
