package cmd

import (
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout = %v, want > 0 (slowloris)", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout = %v, want > 0 (idle keep-alive)", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Errorf("total Read/WriteTimeout = %v/%v, want 0 (large transfers must not abort)",
			srv.ReadTimeout, srv.WriteTimeout)
	}
	if srv.ReadHeaderTimeout != 60*time.Second || srv.IdleTimeout != 120*time.Second {
		t.Errorf("unexpected timeouts: %+v", srv)
	}
}
