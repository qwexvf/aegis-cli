package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRunGenKey_OutputShape(t *testing.T) {
	var buf bytes.Buffer
	if err := runGenKey(&buf); err != nil {
		t.Fatalf("runGenKey: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"key:    aegis_",
		"sha256: ",
		"INSERT INTO submit_api_key (key_hash, name) VALUES ('",
		"export AEGIS_API_KEY=aegis_",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gen-key output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestRunGenKey_KeyAndDigestMatch(t *testing.T) {
	// The printed sha256 must be the hash of the printed key — the
	// whole point of the SQL line.
	var buf bytes.Buffer
	if err := runGenKey(&buf); err != nil {
		t.Fatalf("runGenKey: %v", err)
	}

	key := mustExtract(t, buf.String(), "key:    ")
	digest := mustExtract(t, buf.String(), "sha256: ")

	got := sha256.Sum256([]byte(key))
	if hex.EncodeToString(got[:]) != digest {
		t.Fatalf("printed sha256 (%s) does not match sha256(key=%s)", digest, key)
	}
}

func TestRunGenKey_Random(t *testing.T) {
	// Two calls must produce distinct keys. If we somehow regress to
	// a deterministic source, this catches it cheap.
	var a, b bytes.Buffer
	_ = runGenKey(&a)
	_ = runGenKey(&b)
	if a.String() == b.String() {
		t.Fatal("two gen-key invocations produced identical output")
	}
}

func mustExtract(t *testing.T, s, prefix string) string {
	t.Helper()
	for line := range strings.SplitSeq(s, "\n") {
		if after, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(after)
		}
	}
	t.Fatalf("could not find %q in output:\n%s", prefix, s)
	return ""
}
