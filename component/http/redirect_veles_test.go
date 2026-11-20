package http

import (
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// hostDialer sends every "<name>:<port>" to 127.0.0.1:<port>, so test servers
// can be reached under different host names.
type hostDialer struct{}

func (hostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}

func (hostDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, fmt.Errorf("not supported")
}

type seen struct {
	mu  sync.Mutex
	hdr []stdhttp.Header
}

func (s *seen) add(h stdhttp.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hdr = append(s.hdr, h.Clone())
}

func (s *seen) last(t *testing.T) stdhttp.Header {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hdr) == 0 {
		t.Fatal("server got no request")
	}
	return s.hdr[len(s.hdr)-1]
}

func port(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, p, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// redirector answers 302 to the URL returned by next.
func redirector(s *seen, next func(r *stdhttp.Request) string) *httptest.Server {
	return httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.add(r.Header)
		stdhttp.Redirect(w, r, next(r), stdhttp.StatusFound)
	}))
}

func final(s *seen) *httptest.Server {
	return httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.add(r.Header)
		io.WriteString(w, "ok")
	}))
}

var deviceHeaders = map[string][]string{
	"x-hwid":         {"hwid-1"},
	"x-device-os":    {"Android"},
	"x-ver-os":       {"15"},
	"x-device-model": {"Pixel"},
	"x-test-fleet":    {"k"},
	"X-Api-Key":      {"key-1"},
	"User-Agent":     {"ClashMetaForAndroid/test"},
	"Accept":         {"*/*"},
}

func get(t *testing.T, url string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := HttpRequest(ctx, url, stdhttp.MethodGet, deviceHeaders, nil, WithDialer(hostDialer{}))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func assertNoDevice(t *testing.T, h stdhttp.Header) {
	t.Helper()
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-") {
			t.Errorf("header %s = %q leaked to the other host", k, h[k])
		}
	}
}

func assertDevice(t *testing.T, h stdhttp.Header) {
	t.Helper()
	for k, v := range deviceHeaders {
		if got := h.Get(k); got != v[0] {
			t.Errorf("header %s = %q, want %q", k, got, v[0])
		}
	}
}

func TestVelesRedirectOtherHostDropsRefererAndDeviceHeaders(t *testing.T) {
	var sb seen
	b := final(&sb)
	defer b.Close()
	var sa seen
	a := redirector(&sa, func(*stdhttp.Request) string { return "http://b.test:" + port(t, b) + "/cfg" })
	defer a.Close()

	body, err := get(t, "http://a.test:"+port(t, a)+"/sub/SECRET-TOKEN")
	if err != nil || body != "ok" {
		t.Fatalf("body %q, err %v", body, err)
	}
	assertDevice(t, sa.last(t))
	h := sb.last(t)
	if ref := h.Get("Referer"); ref != "" {
		t.Errorf("Referer %q sent to the other host", ref)
	}
	assertNoDevice(t, h)
	if h.Get("User-Agent") != "ClashMetaForAndroid/test" || h.Get("Accept") != "*/*" {
		t.Errorf("ordinary headers lost: %v", h)
	}
}

func TestVelesRedirectSameHostKeepsDeviceHeadersWithoutReferer(t *testing.T) {
	var sb seen
	b := final(&sb)
	defer b.Close()
	var sa seen
	// same host name in another case and on another port: still the same host
	a := redirector(&sa, func(*stdhttp.Request) string { return "http://A.TEST:" + port(t, b) + "/cfg" })
	defer a.Close()

	body, err := get(t, "http://a.test:"+port(t, a)+"/sub/SECRET-TOKEN")
	if err != nil || body != "ok" {
		t.Fatalf("body %q, err %v", body, err)
	}
	h := sb.last(t)
	if ref := h.Get("Referer"); ref != "" {
		t.Errorf("Referer %q sent on same-host redirect", ref)
	}
	assertDevice(t, h)
}

func TestVelesRedirectChainOfTwo(t *testing.T) {
	var sc seen
	c := final(&sc)
	defer c.Close()
	var sb seen
	b := redirector(&sb, func(*stdhttp.Request) string { return "http://a.test:" + port(t, c) + "/final" })
	defer b.Close()
	var sa seen
	a := redirector(&sa, func(*stdhttp.Request) string { return "http://b.test:" + port(t, b) + "/hop" })
	defer a.Close()

	body, err := get(t, "http://a.test:"+port(t, a)+"/sub/SECRET-TOKEN")
	if err != nil || body != "ok" {
		t.Fatalf("body %q, err %v", body, err)
	}
	assertNoDevice(t, sb.last(t))
	// back on the original host after a foreign hop: the foreign hop chose
	// this URL, so device headers stay dropped
	h := sc.last(t)
	assertNoDevice(t, h)
	if ref := h.Get("Referer"); ref != "" {
		t.Errorf("Referer %q sent", ref)
	}
	if h.Get("User-Agent") != "ClashMetaForAndroid/test" {
		t.Errorf("User-Agent lost: %v", h)
	}
}

func TestVelesRedirectLimitIsTen(t *testing.T) {
	var sf seen
	f := final(&sf)
	defer f.Close()
	var sl seen
	// /n/<k> redirects to /n/<k-1>; /n/0 redirects to the final server
	var loop *httptest.Server
	loop = redirector(&sl, func(r *stdhttp.Request) string {
		var k int
		fmt.Sscanf(r.URL.Path, "/n/%d", &k)
		if k == 0 {
			return "http://a.test:" + port(t, f) + "/"
		}
		return fmt.Sprintf("http://a.test:%s/n/%d", port(t, loop), k-1)
	})
	defer loop.Close()

	// same as the net/http default policy (len(via) >= 10): 10 requests in
	// total, so /n/8 (9 redirects) passes and /n/9 (10th redirect) is refused
	if body, err := get(t, "http://a.test:"+port(t, loop)+"/n/8"); err != nil || body != "ok" {
		t.Fatalf("9 redirects: body %q, err %v", body, err)
	}
	_, err := get(t, "http://a.test:"+port(t, loop)+"/n/9")
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("10 redirects: err %v, want stopped after 10 redirects", err)
	}
}

func TestVelesDirectRequestUnchanged(t *testing.T) {
	var sa seen
	a := final(&sa)
	defer a.Close()

	hdr := map[string][]string{"Referer": {"http://origin.test/page"}}
	for k, v := range deviceHeaders {
		hdr[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := HttpRequest(ctx, "http://a.test:"+port(t, a)+"/sub/SECRET-TOKEN", stdhttp.MethodGet, hdr, nil, WithDialer(hostDialer{}))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := sa.last(t)
	assertDevice(t, h)
	if ref := h.Get("Referer"); ref != "http://origin.test/page" {
		t.Errorf("Referer %q, want the caller's value on a direct request", ref)
	}
}

func TestVelesRedirectOtherHostDropsCallerReferer(t *testing.T) {
	var sb seen
	b := final(&sb)
	defer b.Close()
	var sa seen
	a := redirector(&sa, func(*stdhttp.Request) string { return "http://b.test:" + port(t, b) + "/cfg" })
	defer a.Close()

	hdr := map[string][]string{"Referer": {"http://origin.test/page"}, "X-Hwid": {"hwid-1"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := HttpRequest(ctx, "http://a.test:"+port(t, a)+"/sub/SECRET-TOKEN", stdhttp.MethodGet, hdr, nil, WithDialer(hostDialer{}))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := sa.last(t); got.Get("X-Hwid") != "hwid-1" || got.Get("Referer") != "http://origin.test/page" {
		t.Errorf("direct hop lost caller headers: %v", got)
	}
	h := sb.last(t)
	if ref := h.Get("Referer"); ref != "" {
		t.Errorf("Referer %q sent to the other host", ref)
	}
	assertNoDevice(t, h)
}
