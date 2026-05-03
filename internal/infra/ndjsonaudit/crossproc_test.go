package ndjsonaudit

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// TestWriter_CrossProcessAppend re-execs the test binary as N child
// processes that each append M entries to a shared audit file. Without
// flock, parallel O_APPEND from independent FDs can interleave and
// produce malformed lines under contention. With flock, every line is
// well-formed JSON and the count adds up exactly.
func TestWriter_CrossProcessAppend(t *testing.T) {
	const childMarker = "AEGIS_AUDIT_CROSSPROC_CHILD"
	const childPath = "AEGIS_AUDIT_CROSSPROC_PATH"
	const childCount = "AEGIS_AUDIT_CROSSPROC_N"

	// Child path: write N lines to the audit file at PATH and exit.
	if marker := os.Getenv(childMarker); marker != "" {
		path := os.Getenv(childPath)
		n, _ := strconv.Atoi(os.Getenv(childCount))
		w := NewAt(path).WithProvenance("test", marker, "")
		for i := range n {
			_ = w.Write(outcome("p"+marker, strconv.Itoa(i),
				domain.DecisionAllow, domain.ActionProceed))
		}
		os.Exit(0)
	}

	const procs = 6
	const perProc = 40
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")

	var wg sync.WaitGroup
	for i := range procs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestWriter_CrossProcessAppend")
			cmd.Env = append(os.Environ(),
				childMarker+"="+strconv.Itoa(i),
				childPath+"="+auditPath,
				childCount+"="+strconv.Itoa(perProc),
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("child %d: %v\n%s", i, err, out)
			}
		}(i)
	}
	wg.Wait()

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()

	lines := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		lines++
		var dto entryDTO
		if err := json.Unmarshal(s.Bytes(), &dto); err != nil {
			t.Fatalf("line %d malformed JSON: %q (err: %v)", lines, s.Bytes(), err)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if want := procs * perProc; lines != want {
		t.Errorf("expected %d lines, got %d (loss = corruption or race)", want, lines)
	}
}
