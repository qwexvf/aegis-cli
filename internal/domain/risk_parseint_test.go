package domain

import "testing"

func TestParseInt(t *testing.T) {
	tests := []struct {
		in string
		n  int
		ok bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{"1", 1, true},
		{"4", 4, true},
		{"42", 42, true},
		{"1234", 1234, true},
		{"abc", 0, false},
		{"1a", 0, false},
		{"-1", 0, false}, // minus sign rejected (versions never negative)

		// overflow guard — pathological input gets clamped, not wrapped
		{"99999999999999999999", 1_000_000_000, true},
		{"1000000000000", 1_000_000_000, true},
		{"99999", 99999, true}, // below cap, exact

		// boundary — exactly the cap
		{"1000000000", 1_000_000_000, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			n, ok := parseInt(tc.in)
			if ok != tc.ok || n != tc.n {
				t.Errorf("parseInt(%q) = (%d, %v); want (%d, %v)", tc.in, n, ok, tc.n, tc.ok)
			}
		})
	}
}
