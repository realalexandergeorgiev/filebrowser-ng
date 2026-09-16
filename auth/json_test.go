package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A hanging verification host must fail fast instead of blocking logins.
func TestReCaptchaTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	old := reCaptchaHTTPTimeout
	reCaptchaHTTPTimeout = 100 * time.Millisecond
	defer func() { reCaptchaHTTPTimeout = old }()

	start := time.Now()
	ok, err := (&ReCaptcha{Host: srv.URL, Secret: "s"}).Ok("response")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("verification blocked for %v", elapsed)
	}
	if err == nil {
		t.Fatalf("expected timeout error, got ok=%v", ok)
	}
	if ok {
		t.Fatalf("hanging host must not verify")
	}
}
