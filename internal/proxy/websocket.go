package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	for _, v := range r.Header["Connection"] {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// proxyWebSocket hijacks the client connection and splices it with a backend
// TCP connection for WebSocket passthrough. httputil.ReverseProxy does not
// support WebSocket upgrades, so we handle them manually.
func proxyWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL, routeHost, gatewayToken, userID, userEmail, proxySecret string) {
	// Determine backend address, adding default port if needed.
	backendAddr := target.Host
	if _, _, err := net.SplitHostPort(backendAddr); err != nil {
		if target.Scheme == "https" || target.Scheme == "wss" {
			backendAddr = net.JoinHostPort(backendAddr, "443")
		} else {
			backendAddr = net.JoinHostPort(backendAddr, "80")
		}
	}

	// Hijack the client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Server does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[dashboard-ws] hijack failed: %v", err)
		return
	}

	// Dial the backend.
	var backendConn net.Conn
	if target.Scheme == "https" || target.Scheme == "wss" {
		// Use routeHost for SNI so nginx ingress matches the right rule.
		// Skip TLS verify since the ingress uses a self-signed cert.
		sni := routeHost
		if h, _, splitErr := net.SplitHostPort(routeHost); splitErr == nil {
			sni = h
		}
		backendConn, err = tls.Dial("tcp", backendAddr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	} else {
		backendConn, err = net.Dial("tcp", backendAddr)
	}
	if err != nil {
		log.Printf("[dashboard-ws] backend connect failed addr=%s: %v", backendAddr, err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGateway unreachable"))
		clientConn.Close()
		return
	}

	// Build upstream path with query parameters.
	upstreamPath := r.URL.Path
	if upstreamPath == "" {
		upstreamPath = "/"
	}
	q := r.URL.Query()
	if gatewayToken != "" {
		q.Set("token", gatewayToken)
	}
	if encoded := q.Encode(); encoded != "" {
		upstreamPath += "?" + encoded
	}

	// Build the HTTP upgrade request.
	var reqBuf strings.Builder
	reqBuf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", upstreamPath))

	hostWritten := false
	for key, vals := range r.Header {
		lower := strings.ToLower(key)
		switch lower {
		case "host":
			reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", routeHost))
			hostWritten = true
		case "origin":
			reqBuf.WriteString(fmt.Sprintf("Origin: %s://%s\r\n", target.Scheme, routeHost))
		default:
			for _, v := range vals {
				reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
			}
		}
	}
	if !hostWritten {
		reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", routeHost))
	}
	reqBuf.WriteString(fmt.Sprintf("X-User-ID: %s\r\n", userID))
	reqBuf.WriteString(fmt.Sprintf("X-User-Email: %s\r\n", userEmail))
	if proxySecret != "" {
		reqBuf.WriteString(fmt.Sprintf("X-Proxy-Secret: %s\r\n", proxySecret))
	}
	reqBuf.WriteString("\r\n")

	// Send the upgrade request to the backend.
	_, err = backendConn.Write([]byte(reqBuf.String()))
	if err != nil {
		log.Printf("[dashboard-ws] backend write failed: %v", err)
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

	// Bidirectional splice.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, backendConn)
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