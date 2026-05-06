package locksnap

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParsePomXml(t *testing.T) {
	pom := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>incomplete</groupId>
      <artifactId>missing-version</artifactId>
    </dependency>
  </dependencies>
</project>
`)

	deps, err := parsePomXml(pom, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps (test scope and incomplete excluded), got %d: %+v", len(deps), deps)
	}

	want := map[string]string{
		"org.apache.logging.log4j:log4j-core": "2.14.1",
		"com.google.guava:guava":              "31.1-jre",
	}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoMaven {
			t.Errorf("expected ecosystem maven, got %s", d.Ecosystem)
		}
		if !d.Direct {
			t.Errorf("pom.xml deps should be marked direct, %s wasn't", d.Name)
		}
		v, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %s@%s", d.Name, d.Version)
			continue
		}
		if d.Version != v {
			t.Errorf("%s: want %s, got %s", d.Name, v, d.Version)
		}
	}
}

func TestParsePomXml_Empty(t *testing.T) {
	deps, err := parsePomXml([]byte(`<?xml version="1.0"?><project/>`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Errorf("empty project should produce 0 deps, got %d", len(deps))
	}
}

func TestParsePomXml_Malformed(t *testing.T) {
	_, err := parsePomXml([]byte("not xml"), nil)
	if err == nil {
		t.Error("malformed XML should produce an error")
	}
}

func TestParseGradleLockfile(t *testing.T) {
	raw := []byte(`# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor,testAnnotationProcessor
`)

	deps, err := parseGradleLockfile(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("want 3 deps, got %d: %+v", len(deps), deps)
	}

	want := map[string]string{
		"com.google.guava:guava":              "31.1-jre",
		"org.apache.logging.log4j:log4j-core": "2.14.1",
		"junit:junit":                         "4.13.2",
	}
	for _, d := range deps {
		if d.Ecosystem != domain.EcoMaven {
			t.Errorf("expected ecosystem maven, got %s", d.Ecosystem)
		}
		v, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %s@%s", d.Name, d.Version)
			continue
		}
		if d.Version != v {
			t.Errorf("%s: want %s, got %s", d.Name, v, d.Version)
		}
	}
}

func TestRegistry_HasMaven(t *testing.T) {
	have := map[string]bool{}
	for _, p := range Registered() {
		have[p.Filename()] = true
	}
	for _, want := range []string{"pom.xml", "gradle.lockfile"} {
		if !have[want] {
			t.Errorf("expected %q in registry, missing", want)
		}
	}
}
