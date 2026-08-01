package pmwrapper

import (
	"reflect"
	"testing"
)

func TestAURHelper_IsInstallCommand(t *testing.T) {
	paru := NewParu()
	pac := NewPacman()
	cases := []struct {
		name   string
		h      *AURHelper
		argv   []string
		expect bool
	}{
		{"paru -S pkg", paru, []string{"-S", "firefox"}, true},
		{"paru -Sy pkg", paru, []string{"-Sy", "firefox"}, true},
		{"paru bare install", paru, []string{"firefox"}, true},
		{"paru -Syu no target", paru, []string{"-Syu"}, false},
		{"paru search", paru, []string{"-Ss", "firefox"}, false},
		{"paru remove", paru, []string{"-R", "firefox"}, false},
		{"paru query", paru, []string{"-Q", "firefox"}, false},
		{"pacman -S pkg", pac, []string{"-S", "vim"}, true},
		{"pacman bare arg (no default)", pac, []string{"vim"}, false},
		{"pacman -Syu", pac, []string{"-Syu"}, false},
		{"empty", paru, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.h.IsInstallCommand(c.argv); got != c.expect {
				t.Errorf("IsInstallCommand(%v)=%v want %v", c.argv, got, c.expect)
			}
		})
	}
}

func TestAURHelper_ParseTargets(t *testing.T) {
	paru := NewParu()
	got := paru.ParseTargets([]string{"-S", "--needed", "firefox", "vim", "./local.pkg.tar.zst"})
	want := []string{"firefox", "vim"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseTargets=%v want %v", got, want)
	}
}
