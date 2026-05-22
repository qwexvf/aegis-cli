package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestCocoaPodsParser_Ecosystems(t *testing.T) {
	p := &cocoaPodsParser{}
	ecos := p.Ecosystems()
	if len(ecos) != 1 || ecos[0] != domain.EcoCocoaPods {
		t.Fatalf("Ecosystems() = %v; want [cocoapods]", ecos)
	}
}

func TestCocoaPodsParser_GitDeps(t *testing.T) {
	podspec := []byte(`
Pod::Spec.new do |s|
  s.name = 'MyPod'
  s.version = '1.0.0'
  s.dependency 'AFNetworking', '~> 4.0'
  s.dependency 'CustomLib', :git => 'https://github.com/example/CustomLib.git'
  pod 'AnotherPod', :git => 'https://github.com/other/AnotherPod', :branch => 'main'
end
`)

	p := &cocoaPodsParser{}
	pkg := p.Parse("MyPod", nil, domain.PackageSource{
		Files: map[string][]byte{"MyPod.podspec": podspec},
	})

	gitDeps := filterBySource(pkg.Deps, DepSourceVCS)
	if len(gitDeps) != 2 {
		t.Fatalf("want 2 git deps, got %d: %v", len(gitDeps), pkg.Deps)
	}

	urls := make(map[string]string)
	for _, d := range gitDeps {
		urls[d.Name] = d.Spec
	}
	if urls["CustomLib"] != "https://github.com/example/CustomLib.git" {
		t.Errorf("CustomLib url = %q", urls["CustomLib"])
	}
	if urls["AnotherPod"] != "https://github.com/other/AnotherPod" {
		t.Errorf("AnotherPod url = %q", urls["AnotherPod"])
	}
}

func TestCocoaPodsParser_FileNameVariants(t *testing.T) {
	body := []byte(`s.dependency 'GitDep', :git => 'https://example.com/git.git'`)

	cases := []struct {
		filename string
		want     int
	}{
		{"foo.podspec", 1},
		{"foo.podspec.json", 1},
		{"podspec", 1},
		{"PODSPEC", 1},
		{"Foo.PodSpec", 1},
		{"unrelated.txt", 0},
	}
	for _, tc := range cases {
		t.Run(tc.filename, func(t *testing.T) {
			p := &cocoaPodsParser{}
			pkg := p.Parse("x", nil, domain.PackageSource{
				Files: map[string][]byte{tc.filename: body},
			})
			if len(pkg.Deps) != tc.want {
				t.Errorf("file %q: got %d deps, want %d", tc.filename, len(pkg.Deps), tc.want)
			}
		})
	}
}

func TestCocoaPodsParser_NoGitNoDep(t *testing.T) {
	podspec := []byte(`
Pod::Spec.new do |s|
  s.dependency 'PlainPod', '~> 1.0'
end
`)
	p := &cocoaPodsParser{}
	pkg := p.Parse("x", nil, domain.PackageSource{
		Files: map[string][]byte{"x.podspec": podspec},
	})
	if len(pkg.Deps) != 0 {
		t.Errorf("plain version dep should not produce VCS dep, got %v", pkg.Deps)
	}
}

func TestCocoaPodsParser_NoManifest(t *testing.T) {
	p := &cocoaPodsParser{}
	pkg := p.Parse("empty", nil, domain.PackageSource{})
	if len(pkg.Deps) != 0 {
		t.Errorf("expected no deps for empty source, got %v", pkg.Deps)
	}
}
