package httpx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// RetryPolicy describes how Do retries a request. Use DefaultRetry for
// the standard exponential-backoff-with-jitter behaviour, or build a
// custom policy when the caller wants different bounds (e.g. tarball
// downloads can afford more attempts).
type RetryPolicy struct {
	// MaxAttempts including the first try. 1 = no retry.
	MaxAttempts int
	// Base delay; first retry waits Base, second 2*Base, third 4*Base...
	Base time.Duration
	// Max delay between retries; backoff is clamped here.
	MaxDelay time.Duration
}

// DefaultRetry: 4 total attempts, 200ms → 400ms → 800ms (clamped at
// 2s) with ±20% jitter. Suitable for idempotent reads and the Aegis
// API's reports endpoint (server-side dedup keyed by reporter+pkg).
var DefaultRetry = RetryPolicy{
	MaxAttempts: 4,
	Base:        200 * time.Millisecond,
	MaxDelay:    2 * time.Second,
}

// NoRetry is the explicit "do not retry" policy. Pass when the caller
// has confirmed the operation is unsafe to repeat.
var NoRetry = RetryPolicy{MaxAttempts: 1}

// Do performs req with retries on transient failures. Returns the
// final response (which the caller still owns and must close) or the
// error from the last attempt.
//
// What "transient" means here:
//   - 5xx responses (the server told us to come back).
//   - net.OpError-class errors (DNS, dial, TLS, connection reset).
//   - 429 with optional Retry-After honoured.
//
// Not retried:
//   - 4xx other than 408/429 — those are caller errors and won't
//     improve on retry.
//   - context cancellation — surfaces immediately.
//
// Body handling: Do snapshots req.Body on first call so retries can
// re-send it. Callers passing a non-rewindable body (e.g. a streaming
// reader) will only get the first attempt for body bytes, which is
// fine — the snapshot is invisible to the caller.
func Do(ctx context.Context, client *http.Client, req *http.Request, policy RetryPolicy) (*http.Response, error) {
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}
	body, rewind, err := snapshotBody(req)
	if err != nil {
		return nil, fmt.Errorf("httpx: snapshot body: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// On retries, rebuild the body reader.
		if attempt > 1 && rewind {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
			if !shouldRetry(doErr, policy, attempt) {
				return nil, doErr
			}
			waitOrCancel(ctx, backoff(policy, attempt, 0))
			continue
		}
		if !shouldRetryStatus(resp.StatusCode) || attempt == policy.MaxAttempts {
			return resp, nil
		}
		// Retryable status — drain + close before the next attempt.
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("httpx: HTTP %d", resp.StatusCode)
		waitOrCancel(ctx, backoff(policy, attempt, retryAfter))
	}
	if lastErr == nil {
		lastErr = errors.New("httpx: retry exhausted")
	}
	return nil, lastErr
}

func snapshotBody(req *http.Request) ([]byte, bool, error) {
	if req.Body == nil {
		return nil, false, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, false, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	if req.GetBody == nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return body, true, nil
}

func shouldRetry(err error, policy RetryPolicy, attempt int) bool {
	if attempt >= policy.MaxAttempts {
		return false
	}
	// Context errors propagate; never retry.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		// net.Error includes timeouts and dial failures — retryable.
		return true
	}
	// Treat unknown errors as transient: it's better to retry once and
	// fail definitively than fail loud on a transient blip.
	return true
}

func shouldRetryStatus(code int) bool {
	return code == 408 || code == 429 || code == 502 || code == 503 || code == 504
}

func backoff(policy RetryPolicy, attempt int, hint time.Duration) time.Duration {
	if hint > 0 {
		// Server-supplied Retry-After always wins.
		if hint > policy.MaxDelay && policy.MaxDelay > 0 {
			return policy.MaxDelay
		}
		return hint
	}
	// 200ms * 2^(attempt-1)
	d := policy.Base << (attempt - 1)
	if policy.MaxDelay > 0 && d > policy.MaxDelay {
		d = policy.MaxDelay
	}
	// ±20% jitter — split tail to avoid thundering-herd retries on the
	// same coordinated failure.
	return jitter(d, 0.20)
}

func waitOrCancel(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// jitter returns d adjusted by ±frac (e.g. frac=0.20 → ±20%).
// Uses crypto/rand for jitter to avoid pulling math/rand into a path
// that might otherwise want a stable seed.
func jitter(d time.Duration, frac float64) time.Duration {
	var u uint64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &u)
	// uniform in [-frac, +frac]
	scale := (float64(u) / float64(^uint64(0))) * 2 * frac
	scale -= frac
	return time.Duration(float64(d) * (1 + scale))
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}
