package proxy

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

// WSProxy handles WebSocket upgrade requests at /gw/{userId}.
// Authentication is via ?token= query parameter (timing-safe comparison).
// It hijacks the client connection and splices it with a raw TCP connection
// to the backend gateway — no WebSocket library needed.
type WSProxy struct {
	GetGateway func(userID string) (addr string, gatewayToken string, ok bool)

	// Tracker, when non-nil, is notified of connection open/close events
	// so the IdleMonitor can detect idle gateways.
	Tracker *ConnectionTracker
}

func (p *WSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract userId from path: /gw/{userId} or /gw/{userId}/...
	path := r.URL.Path
	if !strings.HasPrefix(path, "/gw/") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	rest := path[4:] // strip "/gw/"
	userID := rest
	if idx := strings.Index(rest, "/"); idx >= 0 {
		userID = rest[:idx]
	}
	if userID == "" {
		rejectHTTP(w, http.StatusBadRequest, "Missing user ID")
		return
	}

	// Extract token from query.
	token := r.URL.Query().Get("token")
	if token == "" {
		rejectHTTP(w, http.StatusUnauthorized, "Missing gateway token")
		return
	}

	// Look up gateway.
	addr, gatewayToken, ok := p.GetGateway(userID)
	if !ok {
		rejectHTTP(w, http.StatusBadGateway, "Gateway not running")
		return
	}

	// Timing-safe token comparison.
	if !timingSafeEqual(token, gatewayToken) {
		rejectHTTP(w, http.StatusForbidden, "Invalid gateway token")
		return
	}

	// Hijack the client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Server does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		slog.Error("[ws-proxy] hijack failed", "error", err)
		return
	}

	// Connect to the backend gateway.
	backendAddr := addr
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("[ws-proxy] backend connect failed", "addr", backendAddr, "error", err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGateway unreachable"))
		clientConn.Close()
		return
	}

	// Build the upgrade request to replay to the backend.
	// Rewrite the path: strip /gw/{userId} prefix, keep the rest.
	downstreamPath := path[4+len(userID):] // strip "/gw/{userId}"
	if downstreamPath == "" {
		downstreamPath = "/"
	}
	if r.URL.RawQuery != "" {
		downstreamPath += "?" + r.URL.RawQuery
	}

	var reqBuf strings.Builder
	reqBuf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", downstreamPath))

	// Forward headers, rewriting Host and Origin.
	hostWritten := false
	for key, vals := range r.Header {
		lower := strings.ToLower(key)
		switch lower {
		case "host":
			reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", backendAddr))
			hostWritten = true
		case "origin":
			reqBuf.WriteString(fmt.Sprintf("Origin: http://%s\r\n", backendAddr))
		default:
			for _, v := range vals {
				reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
			}
		}
	}
	if !hostWritten {
		reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", backendAddr))
	}
	reqBuf.WriteString("\r\n")

	// Send the upgrade request to the backend.
	_, err = backendConn.Write([]byte(reqBuf.String()))
	if err != nil {
		slog.Error("[ws-proxy] backend write failed", "error", err)
		backendConn.Close()
		clientConn.Close()
		return
	}

	// Flush any buffered data from the hijacked connection to the backend.
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		_, _ = clientBuf.Read(buffered)
		_, _ = backendConn.Write(buffered)
	}

	// Track connection for idle-gateway detection.
	if p.Tracker != nil {
		p.Tracker.Connect(userID)
		defer p.Tracker.Disconnect(userID)
	}

	// Bidirectional splice.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, backendConn)
		// Signal the other direction to finish.
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(backendConn, clientConn)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	backendConn.Close()
	clientConn.Close()
}

// timingSafeEqual performs a constant-time comparison of two strings.
func timingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// rejectHTTP sends an HTTP error before the connection is hijacked.
func rejectHTTP(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(reason))
}
