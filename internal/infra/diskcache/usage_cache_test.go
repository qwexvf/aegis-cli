package diskcache

import (
	"reflect"
	"testing"
)

func TestUsageCache_PutGetRoundTrip(t *testing.T) {
	c := NewUsageCacheAt(t.TempDir())
	want := UsageEntry{
		Imports: map[string]string{
			"lodash":    "lodash",
			"./helpers": "",
		},
		Symbols: map[string][]string{
			"lodash": {"merge", "debounce"},
		},
	}
	sha := FileHash([]byte("source body"))
	if err := c.Put("javascript", sha, want); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("javascript", sha)
	if !ok {
		t.Fatal("Get returned miss after Put")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestUsageCache_MissOnUnknownKey(t *testing.T) {
	c := NewUsageCacheAt(t.TempDir())
	if _, ok := c.Get("javascript", FileHash([]byte("x"))); ok {
		t.Error("expected miss on empty cache")
	}
}

func TestUsageCache_DistinctHashesIsolate(t *testing.T) {
	c := NewUsageCacheAt(t.TempDir())
	a := FileHash([]byte("a"))
	b := FileHash([]byte("b"))
	if a == b {
		t.Fatal("hashes collided")
	}
	_ = c.Put("javascript", a, UsageEntry{Imports: map[string]string{"x": "x"}})
	_ = c.Put("javascript", b, UsageEntry{Imports: map[string]string{"y": "y"}})
	ea, _ := c.Get("javascript", a)
	eb, _ := c.Get("javascript", b)
	if ea.Imports["x"] != "x" || eb.Imports["y"] != "y" {
		t.Errorf("entries cross-contaminated: a=%v b=%v", ea, eb)
	}
}

func TestUsageCache_LanguageNamespaced(t *testing.T) {
	c := NewUsageCacheAt(t.TempDir())
	sha := FileHash([]byte("same source"))
	_ = c.Put("javascript", sha, UsageEntry{Imports: map[string]string{"j": "j"}})
	_ = c.Put("python", sha, UsageEntry{Imports: map[string]string{"p": "p"}})
	js, _ := c.Get("javascript", sha)
	py, _ := c.Get("python", sha)
	if js.Imports["j"] != "j" || py.Imports["p"] != "p" {
		t.Errorf("language namespace leaked: js=%v py=%v", js, py)
	}
}

func TestUsageCache_ClearWipesEntries(t *testing.T) {
	c := NewUsageCacheAt(t.TempDir())
	sha := FileHash([]byte("x"))
	_ = c.Put("javascript", sha, UsageEntry{Imports: map[string]string{"x": "x"}})
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("javascript", sha); ok {
		t.Error("expected miss after Clear")
	}
}
