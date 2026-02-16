package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")

		// Inject a script into HTML responses that sets the gateway WebSocket
		// URL to use the /workspace/ path. The tenant app reads its gatewayUrl
		// from localStorage on boot. By pre-setting it, the WebSocket connects
		// through the proxy instead of to the bare root.
		if opts.StripPrefix == "/workspace" &&
			strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			// Build the WebSocket URL from the request host.
			wsURL := fmt.Sprintf("wss://%s/workspace", resp.Request.Host)
			script := fmt.Sprintf(
				`<script>(`+
					`function(){`+
					`var k="openclaw.control.settings.v1",s=localStorage.getItem(k);`+
					`var o=s?JSON.parse(s):{};`+
					`o.gatewayUrl=%q;`+
					`localStorage.setItem(k,JSON.stringify(o))`+
					`})()</script>`, wsURL)

			// Insert before </head>
			modified := strings.Replace(string(body), "</head>", script+"</head>", 1)
			resp.Body = io.NopCloser(bytes.NewReader([]byte(modified)))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
		}

		return nil
	}

	return proxy
}
