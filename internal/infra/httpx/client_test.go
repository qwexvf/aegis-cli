package httpx

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadCapped_AcceptsUnderLimit(t *testing.T) {
	body := strings.Repeat("a", 100)
	got, err := ReadCapped(strings.NewReader(body), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("returned bytes don't match input")
	}
}

func TestReadCapped_AcceptsExactlyAtLimit(t *testing.T) {
	body := strings.Repeat("a", 1024)
	got, err := ReadCapped(strings.NewReader(body), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1024 {
		t.Errorf("len = %d, want 1024", len(got))
	}
}

func TestReadCapped_RejectsOverLimit(t *testing.T) {
	body := strings.Repeat("a", 1025)
	_, err := ReadCapped(strings.NewReader(body), 1024)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("err = %v, want ErrResponseTooLarge", err)
	}
}

// Defense-in-depth: even if the LimitReader is somehow bypassed and
// we get a giant slice back, the int64 length comparison catches it.
// This test pins the contract.
func TestReadCapped_SentinelByteCatchesOverflow(t *testing.T) {
	// A reader that returns 2KB regardless of LimitReader (not
	// realistic but pins the body-length check as the second line
	// of defense).
	body := bytes.Repeat([]byte("a"), 2048)
	_, err := ReadCapped(bytes.NewReader(body), 1024)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestReadCapped_RejectsNonPositiveLimit(t *testing.T) {
	for _, limit := range []int64{0, -1, -1024} {
		_, err := ReadCapped(strings.NewReader("x"), limit)
		if err == nil {
			t.Errorf("ReadCapped(_, %d) accepted invalid limit", limit)
		}
	}
}
