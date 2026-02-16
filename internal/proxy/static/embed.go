// Package static embeds static assets served by the proxy layer.
package static

import _ "embed"

// LoginHTML is the login/signup page served at /login on the dashboard host.
//
//go:embed login.html
var LoginHTML []byte

// LoadingHTML is the friendly "workspace starting" page shown when a tenant
// pod is booting or temporarily unreachable.
//
//go:embed loading.html
var LoadingHTML []byte
