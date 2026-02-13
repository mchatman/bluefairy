// Package proxy provides reverse-proxy handlers that replace the Node.js
// UI proxy, WebSocket proxy, and Caddy layer in the Aware Platform.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
)

// UIProxy handles all /chat/* requests.
// It authenticates the user, finds their gateway, and reverse-proxies to it.
// For HTML responses, it injects JavaScript for:
//  1. Setting the WebSocket URL in localStorage
//  2. Silent token refresh timer (every 13 min)
//  3. Logout button in the dashboard topbar
type UIProxy struct {
	JWTSecret  string
	GetGateway func(userID string) (addr string, gatewayToken string, ok bool)
}

func (p *UIProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, err := p.extractUser(r)
	if err != nil {
		if wantsHTML(r) {
			http.Redirect(w, r, "/?error=login_required", http.StatusFound)
			return
		}
		writeJSONError(w, http.StatusUnauthorized, "auth/not_authenticated", "Not authenticated")
		return
	}

	addr, gatewayToken, ok := p.GetGateway(userID)
	if !ok {
		if wantsHTML(r) {
			http.Redirect(w, r, "/?error=gateway_not_running", http.StatusFound)
			return
		}
		writeJSONError(w, http.StatusBadGateway, "gateway/not_running", "Gateway not running")
		return
	}

	// Determine WebSocket URL components for script injection.
	wsProto := "ws"
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		wsProto = "wss"
	}
	wsHost := r.Header.Get("X-Forwarded-Host")
	if wsHost == "" {
		wsHost = r.Host
	}
	if wsHost == "" {
		wsHost = "localhost:8000"
	}

	backendURL := &url.URL{
		Scheme: "http",
		Host:   addr,
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
			req.Host = backendURL.Host

			// Strip /chat prefix from the path.
			path := req.URL.Path
			path = strings.TrimPrefix(path, "/chat")
			if path == "" {
				path = "/"
			}
			req.URL.Path = path

			// Strip X-Frame-Options etc to avoid double-framing issues.
			req.Header.Del("X-Frame-Options")
			req.Header.Del("Content-Security-Policy")
		},
		ModifyResponse: func(resp *http.Response) error {
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				return nil
			}

			// Read the entire HTML body so we can inject our script.
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			// Remove headers the gateway shouldn't control in our frame.
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Content-Security-Policy")

			script := buildInjectedScript(userID, gatewayToken, wsProto, wsHost)
			modified := bytes.Replace(body, []byte("</head>"), []byte(script+"</head>"), 1)

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
			resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("[ui-proxy] backend error", "addr", addr, "error", err)
			writeJSONError(w, http.StatusBadGateway, "gateway/unreachable", "Gateway unreachable")
		},
	}

	rp.ServeHTTP(w, r)
}

// extractUser tries the Authorization header then the aware_token cookie.
// Returns the user ID (JWT subject) or an error.
func (p *UIProxy) extractUser(r *http.Request) (string, error) {
	// Try Authorization header.
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		claims, err := auth.VerifyAccessToken(p.JWTSecret, ah[7:])
		if err == nil {
			return claims.Subject, nil
		}
	}

	// Fall back to cookie.
	if c, err := r.Cookie("aware_token"); err == nil && c.Value != "" {
		claims, err := auth.VerifyAccessToken(p.JWTSecret, c.Value)
		if err == nil {
			return claims.Subject, nil
		}
	}

	return "", fmt.Errorf("no valid auth")
}

// buildInjectedScript returns the <script> block injected before </head>.
func buildInjectedScript(userID, gatewayToken, wsProto, wsHost string) string {
	// Gateway tokens are hex-only; sanitise defensively.
	safeToken := sanitiseHexToken(gatewayToken)
	wsURL := fmt.Sprintf("%s://%s/gw/%s?token=%s", wsProto, wsHost, userID, safeToken)
	// Escape for JS string literal safety.
	wsURL = strings.ReplaceAll(wsURL, "'", `\'`)
	wsURL = strings.ReplaceAll(wsURL, "<", `\x3c`)

	return `<script>
(function(){
  var k='aware.control.settings.v1',s={};
  try{s=JSON.parse(localStorage.getItem(k)||'{}')}catch(e){}
  s.gatewayUrl='` + wsURL + `';
  s.token='` + safeToken + `';
  localStorage.setItem(k,JSON.stringify(s));

  // ── Silent token refresh ──
  var REFRESH_INTERVAL = 13 * 60 * 1000;
  function silentRefresh() {
    var rt;
    try { rt = localStorage.getItem('aware_refresh_token'); } catch(e) {}
    if (!rt) { window.location.href = '/?error=login_required'; return; }
    fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: rt })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.ok) throw new Error('refresh failed');
      var token = data.data.accessToken;
      var newRt = data.data.refreshToken;
      document.cookie = 'aware_token=' + token + '; path=/; max-age=900; SameSite=Lax';
      try { localStorage.setItem('aware_refresh_token', newRt); } catch(e) {}
      console.log('[aware] token refreshed silently');
    })
    .catch(function(err) {
      console.warn('[aware] silent refresh failed:', err);
      try { localStorage.removeItem('aware_refresh_token'); } catch(e) {}
      document.cookie = 'aware_token=; path=/; max-age=0; SameSite=Lax';
      window.location.href = '/?error=login_required';
    });
  }
  setInterval(silentRefresh, REFRESH_INTERVAL);
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      if (document.cookie.indexOf('aware_token=') === -1) {
        silentRefresh();
      }
    }
  });

  // ── Logout button ──
  var tries=0;
  function addLogout(){
    var bar=document.querySelector('.topbar-status')||document.querySelector('.topbar-right');
    if(!bar){if(++tries<30)setTimeout(addLogout,200);return;}
    if(document.querySelector('.aware-logout'))return;
    var a=document.createElement('a');
    a.href='/logout';
    a.className='aware-logout';
    a.title='Log out';
    a.style.cssText='display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:8px;color:#888;text-decoration:none;margin-left:8px;cursor:pointer;transition:color .15s,background .15s;font-size:16px;';
    a.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
    a.onmouseenter=function(){a.style.color='#ff6b6b';a.style.background='rgba(255,107,107,0.1)';};
    a.onmouseleave=function(){a.style.color='#888';a.style.background='transparent';};
    bar.appendChild(a);
  }
  addLogout();
})();
</script>`
}

// sanitiseHexToken strips any non-hex characters from a token string.
func sanitiseHexToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// wantsHTML returns true if the request Accept header indicates an HTML response.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeJSONError sends a standard JSON error response.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, message)
}
