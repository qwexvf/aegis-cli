package phpscan

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/scan/ast"
)

func scan(t *testing.T, src string) *ast.Findings {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := ast.NewFindings()
	s.AnalyzeFile("test.php", []byte(src), f)
	return f
}

func has(f *ast.Findings, c domain.Capability) bool {
	for cap := range f.Capabilities {
		if cap == c {
			return true
		}
	}
	return false
}

const phpPrefix = "<?php\n"

func TestPHP_ShellSpawn(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"exec()", `exec("ls -la");`},
		{"shell_exec()", `shell_exec("whoami");`},
		{"system()", `system("rm -rf /");`},
		{"passthru()", `passthru("ps aux");`},
		{"popen()", `$h = popen("ls", "r");`},
		{"proc_open()", `proc_open("sh", $desc, $pipes);`},
		{"backticks", "$x = `whoami`;"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, phpPrefix+tc.src)
			if !has(f, domain.CapShellSpawn) {
				t.Errorf("expected CapShellSpawn for %q, got %v", tc.src, capList(f))
			}
		})
	}
}

func TestPHP_DynamicEval(t *testing.T) {
	for _, src := range []string{
		`eval($payload);`,
		`assert($code);`,
		`call_user_func($fn, $arg);`,
		`call_user_func_array($fn, $args);`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, phpPrefix+src)
			if !has(f, domain.CapDynamicEval) {
				t.Errorf("expected CapDynamicEval for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPHP_Base64Decode(t *testing.T) {
	for _, src := range []string{
		`$out = base64_decode($payload);`,
		`$out = gzinflate($payload);`,
		`$out = gzuncompress($payload);`,
		`$out = str_rot13($x);`,
		`$out = hex2bin($x);`,
		// canonical webshell chain — multiple decoders nested
		`eval(gzinflate(base64_decode($P)));`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, phpPrefix+src)
			if !has(f, domain.CapBase64Decode) {
				t.Errorf("expected CapBase64Decode for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPHP_NetEgress(t *testing.T) {
	for _, src := range []string{
		`$x = file_get_contents("http://x.test/payload");`,
		`$x = file_get_contents("https://x.test/p");`,
		`$h = fopen("http://x.test/p", "r");`,
		`$ch = curl_init();`,
		`curl_exec($ch);`,
		`$s = fsockopen("host", 80);`,
		`$s = stream_socket_client("tcp://host:80");`,
		`$client->get("http://x");`,
		`$client->post("http://x", $body);`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, phpPrefix+src)
			if !has(f, domain.CapNetEgress) {
				t.Errorf("expected CapNetEgress for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPHP_EnvRead_CredentialFilter(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			"getenv literal",
			`$tok = getenv("AWS_ACCESS_KEY_ID");`,
			[]string{"AWS_ACCESS_KEY_ID"},
		},
		{
			"$_ENV subscript",
			`$tok = $_ENV["GITHUB_TOKEN"];`,
			[]string{"GITHUB_TOKEN"},
		},
		{
			"$_SERVER subscript",
			`$auth = $_SERVER["HTTP_AUTHORIZATION"];`,
			[]string{"HTTP_AUTHORIZATION"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := scan(t, phpPrefix+tc.src)
			for _, want := range tc.want {
				if _, ok := f.EnvReads[want]; !ok {
					t.Errorf("expected env-read %q, got %v", want, envReads(f))
				}
			}
		})
	}
}

func TestPHP_FSWriteOutsideRoot(t *testing.T) {
	for _, src := range []string{
		`file_put_contents("/tmp/x", $data);`,
		`fwrite($h, $data);`,
		`copy("a", "/etc/b");`,
		`rename("a", "/root/b");`,
		`symlink("a", "/usr/local/b");`,
		`move_uploaded_file($_FILES["x"]["tmp_name"], "/var/www/upload");`,
		`mkdir("/tmp/x");`,
		`$h = fopen("/tmp/x", "w");`,
		`$h = fopen("/tmp/x", "a");`,
	} {
		t.Run(src, func(t *testing.T) {
			f := scan(t, phpPrefix+src)
			if !has(f, domain.CapFSWriteOutsideRoot) {
				t.Errorf("expected CapFSWriteOutsideRoot for %q, got %v", src, capList(f))
			}
		})
	}
}

func TestPHP_RawIPLiteral(t *testing.T) {
	src := phpPrefix + `$url = "https://1.2.3.4/payload";`
	f := scan(t, src)
	if !has(f, domain.CapRawIPLiteral) {
		t.Errorf("expected CapRawIPLiteral, got %v", capList(f))
	}
}

func TestPHP_NoFalsePositive(t *testing.T) {
	src := phpPrefix + `
class Greeter {
    public function hello($name) {
        return "hi " . $name;
    }
}
$g = new Greeter();
echo $g->hello("world");
`
	f := scan(t, src)
	if len(f.Capabilities) != 0 {
		t.Errorf("benign code triggered capabilities: %v", capList(f))
	}
}

func capList(f *ast.Findings) []string {
	out := []string{}
	for c := range f.Capabilities {
		out = append(out, c.String())
	}
	return out
}

func envReads(f *ast.Findings) []string {
	out := []string{}
	for k := range f.EnvReads {
		out = append(out, k)
	}
	return out
}
