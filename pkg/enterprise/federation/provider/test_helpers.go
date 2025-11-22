// Copyright External Secrets Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newIPv4Server starts an httptest server bound to IPv4 localhost. Some
// sandboxed environments disallow IPv6 loopback bindings, which causes
// httptest.NewServer to fail.
func newIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: unable to bind IPv4 loopback: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.Start()
	return srv
}
