package usecase

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// slowAnalyzer pauses for `delay` per call and counts the high-water
// mark of concurrent in-flight calls. Used to prove enrichWorkers > 1
// actually overlaps work.
type slowAnalyzer struct {
	delay     time.Duration
	out       domain.Fingerprint
	inflight  int32
	maxInFly  int32
	totalSeen int32
}

func (a *slowAnalyzer) Analyze(ctx context.Context, _ domain.Ecosystem, _ PackageSource) (domain.Fingerprint, error) {
	cur := atomic.AddInt32(&a.inflight, 1)
	defer atomic.AddInt32(&a.inflight, -1)
	for {
		max := atomic.LoadInt32(&a.maxInFly)
		if cur <= max {
			break
		}
		if atomic.CompareAndSwapInt32(&a.maxInFly, max, cur) {
			break
		}
	}
	atomic.AddInt32(&a.totalSeen, 1)
	select {
	case <-ctx.Done():
		return domain.Fingerprint{}, ctx.Err()
	case <-time.After(a.delay):
	}
	return a.out, nil
}

func TestEnrich_RunsInParallel(t *testing.T) {
	const n = 8
	deps := make([]domain.Dependency, n)
	for i := range deps {
		deps[i] = dep("p"+strconv.Itoa(i), "1")
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: deps}

	analyzer := &slowAnalyzer{delay: 30 * time.Millisecond}
	fetcher := &fakeFetcher{}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(fetcher, analyzer, newFPCache())

	start := time.Now()
	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	// With 8 deps × 30ms each, sequential would be 240ms; parallel
	// with workerCount > 1 must be substantially less. Generous
	// threshold to avoid flakes on slow CI.
	if elapsed >= 200*time.Millisecond {
		t.Errorf("enrich took %v; expected parallel speedup", elapsed)
	}
	if max := atomic.LoadInt32(&analyzer.maxInFly); max < 2 {
		t.Errorf("max concurrent in-flight = %d; expected > 1", max)
	}
	if got := atomic.LoadInt32(&analyzer.totalSeen); int(got) != n {
		t.Errorf("expected %d calls, got %d", n, got)
	}

	saved := store.saved["/proj"]
	for _, d := range saved.Deps {
		if d.Fingerprint == nil || !d.Fingerprint.Analyzed {
			t.Errorf("dep %s missing analyzed fingerprint", d.Name)
		}
	}
}

func TestEnrich_HonorsContextCancellation(t *testing.T) {
	const n = 16
	deps := make([]domain.Dependency, n)
	for i := range deps {
		deps[i] = dep("p"+strconv.Itoa(i), "1")
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: deps}

	analyzer := &slowAnalyzer{delay: 100 * time.Millisecond}
	fetcher := &fakeFetcher{}
	pres := &snapshotCapturingPresenter{}
	uc := NewSnapshot(store, &fakeScanner{}, pres, "test").
		WithRiskEngine(fetcher, analyzer, newFPCache())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := uc.Enrich(ctx, "/proj")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected ctx error from cancellation")
	}
	// All 16 sequential would be 1.6s; parallel without cancel ~200ms;
	// with cancel mid-flight should resolve quickly after the inflight
	// workers finish their current iteration.
	if elapsed > 600*time.Millisecond {
		t.Errorf("cancellation slow: %v", elapsed)
	}

	// Partial progress was saved. We don't pin a specific count
	// (timing-dependent), but at least one should have completed.
	saved := store.saved["/proj"]
	analyzed := 0
	for _, d := range saved.Deps {
		if d.Fingerprint != nil && d.Fingerprint.Analyzed {
			analyzed++
		}
	}
	if analyzed >= n {
		t.Errorf("expected partial progress, got all %d analyzed", analyzed)
	}
}

func TestEnrich_ParallelProducesSameFingerprintsAsSequential(t *testing.T) {
	// Determinism check: regardless of completion order, every dep
	// gets the analyzer's output as its fingerprint.
	const n = 12
	deps := make([]domain.Dependency, n)
	for i := range deps {
		deps[i] = dep("p"+strconv.Itoa(i), "1")
	}
	store := newFakeStore()
	store.saved["/proj"] = domain.Snapshot{Deps: deps}

	analyzer := &fakeAnalyzer{out: domain.Fingerprint{
		Capabilities: domain.NewCapabilitySet(domain.CapDynamicEval),
	}}
	uc := NewSnapshot(store, &fakeScanner{}, &snapshotCapturingPresenter{}, "test").
		WithRiskEngine(&fakeFetcher{}, analyzer, newFPCache())

	if err := uc.Enrich(context.Background(), "/proj"); err != nil {
		t.Fatal(err)
	}
	saved := store.saved["/proj"]
	for i, d := range saved.Deps {
		if d.Fingerprint == nil {
			t.Fatalf("dep[%d] missing fingerprint", i)
		}
		if !d.Fingerprint.Analyzed {
			t.Errorf("dep[%d] not marked analyzed", i)
		}
		if !d.Fingerprint.Capabilities.Has(domain.CapDynamicEval) {
			t.Errorf("dep[%d] missing expected capability", i)
		}
	}
}
