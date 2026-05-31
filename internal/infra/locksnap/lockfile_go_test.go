package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseGoSum(t *testing.T) {
	in := []byte(`github.com/spf13/cobra v1.8.0 h1:7aJaZx1B85qltLMc546zn58BxxfZdR/W22ej9CFoEf0=
github.com/spf13/cobra v1.8.0/go.mod h1:WXLWApfZ71AjXPya3WOlMsY9yMs7YeiHhFVlvLyhcho=
github.com/spf13/pflag v1.0.5 h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=
github.com/spf13/pflag v1.0.5/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
golang.org/x/sys v0.43.0 h1:Rlag2XtaFTxp19wS8MXlJwTvoh8ArU6ezoyFsMyCTNI=
golang.org/x/sys v0.43.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
`)
	deps, err := parseGoSum(in, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3 (deduped from h1 + /go.mod pairs)", len(deps))
	}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoGo {
			t.Errorf("ecosystem = %v, want go", d.Ecosystem)
		}
	}
	versions := map[string]string{}
	for _, d := range deps {
		versions[d.Name] = d.Version
	}
	if versions["github.com/spf13/cobra"] != "v1.8.0" {
		t.Errorf("cobra = %q", versions["github.com/spf13/cobra"])
	}
	if versions["golang.org/x/sys"] != "v0.43.0" {
		t.Errorf("x/sys = %q", versions["golang.org/x/sys"])
	}
}

// go.sum lines that aren't real entries (wrong field count, missing v-prefix
// or h1: hash, control-char module names) must be rejected, not smuggled in
// as deps.
func TestParseGoSum_RejectsGarbage(t *testing.T) {
	raw := []byte(`github.com/real/mod v1.2.3 h1:abc=
github.com/real/mod v1.2.3/go.mod h1:abc=
hello world this is not a go.sum line
github.com/evil/mod notaversion h1:xyz=
github.com/evil/mod v1.0.0 notahash
exploit` + "\x00" + `inject v1.0.0 h1:zzz=
`)
	deps, err := parseGoSum(raw, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("want 1 valid dep, got %d: %+v", len(deps), deps)
	}
	if deps[0].Name != "github.com/real/mod" || deps[0].Version != "v1.2.3" {
		t.Errorf("unexpected dep: %+v", deps[0])
	}
}
