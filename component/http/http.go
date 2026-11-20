package http

import (
	"context"
	"errors"
	"io"
	"net"
	URL "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"

	"github.com/metacubex/http"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, options ...Option) (*http.Response, error) {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UA())
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(opt.caOption)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// from http.DefaultTransport
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if opt.dialer != nil {
				return opt.dialer.DialContext(ctx, network, address)
			}
			if conn, err := inner.HandleTcp(inner.GetTunnel(), address, opt.specialProxy); err == nil {
				return conn, nil
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport, CheckRedirect: checkRedirect}
	return client.Do(req)
}

// maxRedirects is the limit of the default net/http policy.
const maxRedirects = 10

// keptOnCrossHost are the device headers a subscription panel needs to
// register the device: the Android app sends them with the subscription
// download, the panel reads x-hwid and the device description. Old
// subscription links answer 301 to another domain, and without x-hwid there
// the panel would treat the device as unknown, so these survive a cross-host
// redirect. Lower case, compared without regard to case. Never add anything
// secret (tokens, API keys) here. (P35)
var keptOnCrossHost = map[string]struct{}{
	"x-hwid":         {},
	"x-device-os":    {},
	"x-ver-os":       {},
	"x-device-model": {},
	"x-app-version":  {},
}

// checkRedirect keeps the default limit and follows redirects to any host, but
// never sends Referer (it would carry the previous URL, which may hold a
// subscription token) and, once the chain has left the original host, drops
// every X-* header (custom headers set for the original server) except the
// device headers in keptOnCrossHost (P35). The http client itself only strips
// Authorization and Cookie, and copies the original headers again on every
// hop, so the whole chain is checked each time. (P28)
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("stopped after 10 redirects")
	}
	req.Header.Del("Referer")
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL.Hostname()
	crossHost := !strings.EqualFold(req.URL.Hostname(), origin)
	for _, r := range via[1:] {
		if !strings.EqualFold(r.URL.Hostname(), origin) {
			crossHost = true
		}
	}
	if crossHost {
		for k := range req.Header {
			if len(k) < 2 || !strings.EqualFold(k[:2], "x-") {
				continue
			}
			if _, keep := keptOnCrossHost[strings.ToLower(k)]; !keep {
				delete(req.Header, k)
			}
		}
	}
	return nil
}

type Option func(opt *option)

type option struct {
	specialProxy string
	dialer       C.Dialer
	caOption     ca.Option
}

func WithSpecialProxy(name string) Option {
	return func(opt *option) {
		opt.specialProxy = name
	}
}

func WithDialer(dialer C.Dialer) Option {
	return func(opt *option) {
		opt.dialer = dialer
	}
}

func WithCAOption(caOption ca.Option) Option {
	return func(opt *option) {
		opt.caOption = caOption
	}
}
