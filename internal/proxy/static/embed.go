// Package static embeds static assets served by the proxy layer.
package static

import _ "embed"

//go:embed login.html
var LoginHTML []byte
