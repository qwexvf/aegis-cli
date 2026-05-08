package vulnlookup

import (
	"context"
	"sync"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// MultiSource queries all sources concurrently and merges the results.
// Advisory deduplication is by ID — when two sources return the same
// advisory ID the one with the higher severity wins, and aliases are
// unioned. A source that returns an error is skipped (its results are
// dropped); the merged result is returned as long as at least one
// source succeeds. If all sources fail the last error is returned.
type MultiSource struct {
	Sources []usecase.VulnLookup
}

// Lookup implements usecase.VulnLookup.
func (m MultiSource) Lookup(ctx context.Context, queries []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	if len(m.Sources) == 0 {
		return nil, nil
	}
	if len(m.Sources) == 1 {
		return m.Sources[0].Lookup(ctx, queries)
	}

	type result struct {
		data map[string][]domain.Advisory
		err  error
	}
	results := make([]result, len(m.Sources))
	var wg sync.WaitGroup
	for i, src := range m.Sources {
		wg.Add(1)
		go func(idx int, s usecase.VulnLookup) {
			defer wg.Done()
			data, err := s.Lookup(ctx, queries)
			results[idx] = result{data: data, err: err}
		}(i, src)
	}
	wg.Wait()

	merged := make(map[string][]domain.Advisory, len(queries))
	for _, q := range queries {
		merged[q.Key()] = []domain.Advisory{}
	}

	var lastErr error
	anyOK := false
	for _, r := range results {
		if r.err != nil {
			lastErr = r.err
			continue
		}
		anyOK = true
		for key, advs := range r.data {
			merged[key] = mergeAdvisories(merged[key], advs)
		}
	}
	if !anyOK {
		return nil, lastErr
	}
	return merged, nil
}

// mergeAdvisories unions two advisory slices, deduplicating by ID.
// When both sides have the same ID the higher severity wins; aliases
// are unioned.
func mergeAdvisories(base, incoming []domain.Advisory) []domain.Advisory {
	if len(incoming) == 0 {
		return base
	}
	idx := make(map[string]int, len(base))
	for i, a := range base {
		idx[a.ID] = i
	}
	for _, a := range incoming {
		if i, ok := idx[a.ID]; ok {
			if domain.MaxSeverity([]domain.Advisory{a}) > domain.MaxSeverity([]domain.Advisory{base[i]}) {
				base[i].Severity = a.Severity
			}
			base[i].Aliases = unionStrings(base[i].Aliases, a.Aliases)
		} else {
			idx[a.ID] = len(base)
			base = append(base, a)
		}
	}
	return base
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			a = append(a, s)
		}
	}
	return a
}
