package domain

import (
	"reflect"
	"testing"
)

func TestCapability_StringIsStable(t *testing.T) {
	// Stability matters: these strings are written to audit logs +
	// snapshot files. Renaming any is a breaking change.
	want := map[Capability]string{
		CapShellSpawn:         "shell-spawn",
		CapDynamicEval:        "dynamic-eval",
		CapBase64Decode:       "base64-decode",
		CapNetEgress:          "net-egress",
		CapEnvRead:            "env-read",
		CapFSWriteOutsideRoot: "fs-write-outside-root",
		CapRawIPLiteral:       "raw-ip-literal",
		CapInstallHookExec:    "install-hook-exec",
	}
	for c, w := range want {
		if got := c.String(); got != w {
			t.Errorf("%d.String() = %q, want %q", c, got, w)
		}
	}
	if Capability(999).String() != "unknown" {
		t.Errorf("unknown capability should stringify to 'unknown'")
	}
}

func TestAllCapabilities_ContainsEveryNamedCapability(t *testing.T) {
	all := AllCapabilities()
	for c := CapShellSpawn; c <= CapInstallHookExec; c++ {
		found := false
		for _, x := range all {
			if x == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllCapabilities() missing %s", c)
		}
	}
}

func TestNewCapabilitySet_DedupesAndSorts(t *testing.T) {
	got := NewCapabilitySet(CapNetEgress, CapShellSpawn, CapShellSpawn, CapBase64Decode)
	want := CapabilitySet{CapShellSpawn, CapBase64Decode, CapNetEgress}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNewCapabilitySet_Empty(t *testing.T) {
	if got := NewCapabilitySet(); got != nil {
		t.Errorf("empty input should yield nil set, got %v", got)
	}
}

func TestCapabilitySet_Has(t *testing.T) {
	s := NewCapabilitySet(CapShellSpawn, CapNetEgress)
	if !s.Has(CapShellSpawn) {
		t.Error("missing CapShellSpawn")
	}
	if s.Has(CapDynamicEval) {
		t.Error("false positive on CapDynamicEval")
	}
}

func TestCapabilitySet_Union(t *testing.T) {
	a := NewCapabilitySet(CapShellSpawn, CapNetEgress)
	b := NewCapabilitySet(CapNetEgress, CapDynamicEval)
	got := a.Union(b)
	want := CapabilitySet{CapShellSpawn, CapDynamicEval, CapNetEgress}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Union: got %v, want %v", got, want)
	}
}

func TestCapabilitySet_Union_EmptyOperands(t *testing.T) {
	a := NewCapabilitySet(CapShellSpawn)
	if got := a.Union(nil); !reflect.DeepEqual(got, CapabilitySet{CapShellSpawn}) {
		t.Errorf("a ∪ ∅ = %v", got)
	}
	if got := CapabilitySet(nil).Union(a); !reflect.DeepEqual(got, CapabilitySet{CapShellSpawn}) {
		t.Errorf("∅ ∪ a = %v", got)
	}
}

func TestCapabilitySet_Difference(t *testing.T) {
	v1 := NewCapabilitySet(CapShellSpawn, CapBase64Decode)
	v2 := NewCapabilitySet(CapShellSpawn, CapNetEgress, CapDynamicEval, CapBase64Decode)
	added := v2.Difference(v1)
	want := CapabilitySet{CapDynamicEval, CapNetEgress}
	if !reflect.DeepEqual(added, want) {
		t.Errorf("v2 \\ v1 (capabilities added in upgrade): got %v, want %v", added, want)
	}
}

func TestCapabilitySet_Difference_EmptyOperands(t *testing.T) {
	a := NewCapabilitySet(CapShellSpawn)
	if got := a.Difference(nil); !reflect.DeepEqual(got, CapabilitySet{CapShellSpawn}) {
		t.Errorf("a \\ ∅ = %v", got)
	}
	if got := CapabilitySet(nil).Difference(a); got != nil {
		t.Errorf("∅ \\ a = %v, want nil", got)
	}
}
