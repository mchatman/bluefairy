package proxy

import (
	"crypto/tls"
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
	RouteHost   string
	UserID      string
	UserEmail   string
	ProxySecret string
	// StripPrefix removes this path prefix before forwarding (e.g. "/api").
	StripPrefix string
}

// newTenantProxy creates a pre-configured httputil.ReverseProxy that forwards
// requests to a tenant instance with gateway token injection, user headers,
// and correct Host header routing.
func newTenantProxy(opts proxyOpts) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(opts.Target)

	// When connecting via IP to an nginx ingress with a self-signed cert,
	// skip TLS verification and set SNI for correct ingress matching.
	if opts.Target.Scheme == "https" && opts.Instance.Host != "" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         opts.RouteHost,
			},
		}
	}

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
		req.Host = opts.RouteHost
	}

	return proxy
}

// routeHost returns the hostname to use for upstream routing.
// When TENANT_HOST_TEMPLATE is set, inst.Host takes precedence over the
// target URL's host.
func routeHost(target *url.URL, inst *tenant.Instance) string {
	if inst.Host != "" {
		return inst.Host
	}
	return target.Host
}
