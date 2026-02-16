package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/tenant"
)

// proxyOpts configures a reverse proxy to a tenant instance.
type proxyOpts struct {
	Target      *url.URL
	Instance    *tenant.Instance
	UserID      string
	UserEmail   string
	ProxySecret string
	// StripPrefix removes this path prefix before forwarding (e.g. "/api").
	StripPrefix string
}

// newTenantProxy creates a pre-configured httputil.ReverseProxy that forwards
// requests to a tenant instance with gateway token injection, user headers,
// and correct Host header.
func newTenantProxy(opts proxyOpts) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(opts.Target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		if opts.StripPrefix != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, opts.StripPrefix)
		}

		if opts.Instance.Token != "" {
			q := req.URL.Query()
			q.Set("token", opts.Instance.Token)
			req.URL.RawQuery = q.Encode()
		}

		req.Header.Set("X-User-ID", opts.UserID)
		req.Header.Set("X-User-Email", opts.UserEmail)
		if opts.ProxySecret != "" {
			req.Header.Set("X-Proxy-Secret", opts.ProxySecret)
		}
		req.Host = opts.Target.Host
	}

	return proxy
}
