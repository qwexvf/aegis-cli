package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo_RetriesOn503ThenSucceeds(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: 5 * time.Second})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	policy := RetryPolicy{MaxAttempts: 4, Base: 5 * time.Millisecond, MaxDelay: 50 * time.Millisecond}

	resp, err := Do(context.Background(), client, req, policy)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if got := atomic.LoadInt64(&hits); got != 3 {
		t.Fatalf("expected 3 hits (2 retries + success), got %d", got)
	}
}

func TestDo_NoRetryOn400(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: 5 * time.Second})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL,
		strings.NewReader(`{}`))
	policy := RetryPolicy{MaxAttempts: 4, Base: 5 * time.Millisecond}

	resp, err := Do(context.Background(), client, req, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 surfaced, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("expected 1 hit (no retry on 4xx), got %d", got)
	}
}

func TestDo_HonoursContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: 5 * time.Second})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	policy := RetryPolicy{MaxAttempts: 10, Base: 100 * time.Millisecond, MaxDelay: time.Second}

	start := time.Now()
	_, err := Do(ctx, client, req.WithContext(ctx), policy)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		// Could surface as the last 503 if context is observed only
		// during backoff; that's also acceptable. Assert "fast exit".
		if elapsed > 500*time.Millisecond {
			t.Fatalf("cancellation slow (%v): %v", elapsed, err)
		}
	}
}

func TestDo_RetriesNetworkError(t *testing.T) {
	// Point at a port nobody listens on so dial fails.
	client := NewClient(Config{Timeout: 100 * time.Millisecond})
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	policy := RetryPolicy{MaxAttempts: 3, Base: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond}

	_, err := Do(context.Background(), client, req, policy)
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestHeaderInjector_SetsUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(Config{UserAgent: "aegis-cli/test (probe)"})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if got != "aegis-cli/test (probe)" {
		t.Fatalf("got UA %q, want aegis-cli/test (probe)", got)
	}
}

func TestHeaderInjector_DoesNotOverridePerRequest(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(Config{UserAgent: "default"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "explicit")
	resp, _ := client.Do(req)
	resp.Body.Close()
	if got != "explicit" {
		t.Fatalf("expected per-request UA to win, got %q", got)
	}
}

func TestHeaderInjector_SetsRequestID(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(Config{RequestID: "abc-123"})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if got != "abc-123" {
		t.Fatalf("got X-Request-ID %q, want abc-123", got)
	}
}
