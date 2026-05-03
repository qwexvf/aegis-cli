package npmregistry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkConcurrentSamePackage measures the worst case for the
// metadata cache: N goroutines all asking for the same uncached
// package at the same time. Without coalescing this fans out into N
// HTTP requests; the snapshot enrich worker pool can hit this when
// two workers enrich two versions of the same package back-to-back.
//
// The benchmark also reports the actual upstream HTTP-call count via
// b.ReportMetric so a regression that re-introduces fan-out is loud.
func BenchmarkConcurrentSamePackage(b *testing.B) {
	const fanout = 8 // matches enrichWorkers

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		// Realistic-ish latency. Real registry round-trip from a
		// dev workstation is 30–120 ms; 5 ms keeps the bench short
		// while still letting a goroutine race meaningfully.
		time.Sleep(5 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"name":"lodash","dist-tags":{"latest":"4.17.21"},`+
			`"versions":{"4.17.21":{"version":"4.17.21"}}}`)
	}))
	defer srv.Close()

	for i := 0; i < b.N; i++ {
		// Each iteration uses a fresh client so the cache is cold —
		// otherwise we'd be measuring the cache hit, which is a
		// trivially-fast map lookup and not the interesting case.
		client := New(WithRegistry(srv.URL), WithHTTPClient(srv.Client()))
		var wg sync.WaitGroup
		wg.Add(fanout)
		for k := 0; k < fanout; k++ {
			go func() {
				defer wg.Done()
				_, _ = client.Resolve(context.Background(), "lodash", "latest")
			}()
		}
		wg.Wait()
	}

	// Report the per-iteration HTTP calls. Without coalescing this
	// will be `fanout` (one per goroutine); with singleflight it
	// should drop to 1.
	b.ReportMetric(float64(atomic.LoadInt64(&hits))/float64(b.N), "http_calls/op")
}
