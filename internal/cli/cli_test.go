package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeCTFd(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token tok" {
			w.WriteHeader(401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/challenges":
			w.Write([]byte(`{"success":true,"data":[{"id":7,"name":"Pwn One","category":"Binary Exploitation","value":300},
				{"id":8,"name":"web2","category":"web","value":100,"solved_by_me":true}]}`))
		case "GET /api/v1/challenges/7":
			w.Write([]byte(`{"success":true,"data":{"id":7,"name":"Pwn One","category":"Binary Exploitation","value":300,
				"description":"smash it","connection_info":"nc h 1","files":["/files/x/pwn1?token=a"]}}`))
		case "GET /api/v1/challenges/8":
			w.Write([]byte(`{"success":true,"data":{"id":8,"name":"web2","category":"web","value":100,"solved_by_me":true}}`))
		case "POST /api/v1/challenges/attempt":
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			status := "incorrect"
			if b["submission"] == "flag{$ok'\"}" && b["challenge_id"] == float64(7) {
				status = "correct"
			}
			w.Write([]byte(`{"success":true,"data":{"status":"` + status + `","message":"m"}}`))
		case "GET /files/x/pwn1":
			w.Write([]byte("\x7fELF"))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"message":"nope"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func clean(t *testing.T) {
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "CTFX_") || strings.HasPrefix(k, "CTFD_") || strings.HasPrefix(k, "RCTF_") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
}

type result struct {
	code   int
	out    map[string]any
	stdout string
	stderr string
}

func run(t *testing.T, dir, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	app := &App{Version: "test", Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb}
	code := app.Run(context.Background(), append([]string{"-C", dir}, args...))
	r := result{code: code, stdout: out.String(), stderr: errb.String()}
	_ = json.Unmarshal(out.Bytes(), &r.out)
	return r
}

func workspace(t *testing.T, env string) string {
	t.Helper()
	clean(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".ctfx"), 0o755)
	if env != "" {
		os.WriteFile(filepath.Join(root, ".ctfx", "ctfd.env"), []byte(env), 0o600)
	}
	return root
}

func TestListShowSubmit(t *testing.T) {
	srv := fakeCTFd(t)
	root := workspace(t, "CTFD_URL="+srv.URL+"\nCTFD_TOKEN=tok\n")

	r := run(t, root, "", "chal", "ls", "--unsolved")
	if r.code != 0 || r.out["platform"] != "ctfd" || r.out["total"] != float64(1) {
		t.Fatalf("ls: %d %s %s", r.code, r.stdout, r.stderr)
	}
	// Name resolution, and a flag with shell-hostile characters over stdin.
	r = run(t, root, "flag{$ok'\"}\n", "submit", "pwn one")
	res, _ := r.out["result"].(map[string]any)
	if r.code != 0 || res["status"] != "correct" || res["challenge_id"] != "7" {
		t.Fatalf("submit: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = run(t, root, "", "submit", "7", "flag{wrong}")
	if res, _ := r.out["result"].(map[string]any); r.code != 0 || res["status"] != "incorrect" {
		t.Fatalf("wrong flag should exit 0 with status incorrect: %d %s", r.code, r.stdout)
	}
	r = run(t, root, "", "chal", "show", "Pwn One", "--format", "table")
	if r.code != 0 || !strings.Contains(r.stdout, "smash it") || !strings.Contains(r.stdout, "nc h 1") {
		t.Fatalf("show table: %d %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestSubmitLedgerAndOracle(t *testing.T) {
	srv := fakeCTFd(t)
	root := workspace(t, "CTFD_URL="+srv.URL+"\nCTFD_TOKEN=tok\n")
	const good = "flag{$ok'\"}"

	if r := run(t, root, good, "submit", "7"); r.code != 0 || submitOut(r)["status"] != "correct" {
		t.Fatalf("correct submit: %d %s %s", r.code, r.stdout, r.stderr)
	}
	// Same flag on another challenge is short-circuited from the ledger.
	r := run(t, root, good, "submit", "8")
	res := submitOut(r)
	if r.code != 0 || res["status"] != "correct" || !strings.Contains(res["message"].(string), "ledger") {
		t.Fatalf("ledger short-circuit: %d %s", r.code, r.stdout)
	}
	// A wrong flag is recorded, then refused on an identical resend.
	if r := run(t, root, "", "submit", "7", "flag{no}"); r.code != 0 || submitOut(r)["status"] != "incorrect" {
		t.Fatalf("wrong submit: %d %s", r.code, r.stdout)
	}
	if r := run(t, root, "", "submit", "7", "flag{no}"); r.code != ExitUsage {
		t.Fatalf("identical wrong flag should be refused: %d %s", r.code, r.stderr)
	}
	if r := run(t, root, "", "submit", "7", "flag{no}", "--force"); r.code != 0 || submitOut(r)["status"] != "incorrect" {
		t.Fatalf("--force should resend: %d %s", r.code, r.stdout)
	}
	// A failing oracle blocks the submission without contacting the platform.
	r = run(t, root, "", "submit", "7", "flag{oracle}", "--verify", "false")
	if r.code != 0 || submitOut(r)["status"] != "error" {
		t.Fatalf("oracle reject: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if _, ok := priorRejected(root, "ctfd", "ctfd", flagHash("flag{oracle}"), "7"); ok {
		t.Fatal("oracle-rejected flag must not be recorded as a platform rejection")
	}
}

func submitOut(r result) map[string]any {
	m, _ := r.out["result"].(map[string]any)
	return m
}

func TestExitCodes(t *testing.T) {
	srv := fakeCTFd(t)
	root := workspace(t, "CTFD_URL="+srv.URL+"\nCTFD_TOKEN=tok\n")
	cases := []struct {
		args []string
		code int
		kind string
	}{
		{[]string{"bogus"}, ExitUsage, "usage"},
		{[]string{"chal", "show"}, ExitUsage, "usage"},
		{[]string{"chal", "show", "999"}, ExitRemote, "not_found"},
		{[]string{"--platform", "rctf", "chal", "ls"}, ExitConfig, "config"},
	}
	for _, c := range cases {
		r := run(t, root, "", c.args...)
		var e struct {
			Error struct{ Kind string } `json:"error"`
		}
		json.Unmarshal([]byte(r.stderr), &e)
		if r.code != c.code || e.Error.Kind != c.kind {
			t.Errorf("%v: code %d kind %q stderr %s", c.args, r.code, e.Error.Kind, r.stderr)
		}
	}
	bad := workspace(t, "CTFD_URL="+srv.URL+"\nCTFD_TOKEN=wrong\n")
	if r := run(t, bad, "", "solves"); r.code != ExitConfig {
		t.Errorf("auth failure: %d %s", r.code, r.stderr)
	}
	empty := workspace(t, "")
	if r := run(t, empty, "", "chal", "ls"); r.code != ExitConfig {
		t.Errorf("missing config: %d %s", r.code, r.stderr)
	}
}

func TestSyncAndFetch(t *testing.T) {
	srv := fakeCTFd(t)
	root := workspace(t, "CTFD_URL="+srv.URL+"\nCTFD_TOKEN=tok\n")
	r := run(t, root, "", "sync")
	if r.code != 0 {
		t.Fatalf("sync: %s %s", r.stdout, r.stderr)
	}
	dir := filepath.Join(root, "challenges", "pwn", "pwn-one")
	desc, err := os.ReadFile(filepath.Join(dir, "desc.md"))
	if err != nil || !strings.Contains(string(desc), "smash it") {
		t.Fatalf("desc.md: %v %s", err, desc)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "dist", "pwn1")); string(b) != "\x7fELF" {
		t.Fatalf("dist file missing")
	}
	// User notes survive and a second sync changes nothing.
	os.WriteFile(filepath.Join(dir, "desc.md"), []byte("my notes"), 0o644)
	r = run(t, root, "", "sync")
	if r.code != 0 || !strings.Contains(r.stdout, `"kept"`) || strings.Contains(r.stdout, `"created"`) {
		t.Fatalf("resync: %s", r.stdout)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "desc.md")); string(b) != "my notes" {
		t.Fatal("sync overwrote desc.md")
	}
	r = run(t, root, "", "fetch", "7", "-o", "/tmp/elsewhere", "--force")
	if r.code != ExitUsage {
		t.Fatalf("fetch outside root should be refused: %d %s", r.code, r.stderr)
	}
}

func TestInitAndMigrate(t *testing.T) {
	root := workspace(t, "")
	os.Remove(filepath.Join(root, ".ctfx"))
	if r := run(t, root, "", "init", "rctf"); r.code != 0 {
		t.Fatalf("init: %s", r.stderr)
	}
	if r := run(t, root, "", "init", "rctf"); r.code != ExitUsage {
		t.Fatal("init should refuse to overwrite")
	}
	if b, _ := os.ReadFile(filepath.Join(root, ".ctfx", ".gitignore")); !strings.Contains(string(b), "*.env") {
		t.Fatal("gitignore missing")
	}

	legacy := workspace(t, "")
	os.Remove(filepath.Join(legacy, ".ctfx"))
	os.MkdirAll(filepath.Join(legacy, ".opencode/ctf"), 0o755)
	os.WriteFile(filepath.Join(legacy, ".opencode/ctf/ctfd.env"), []byte("CTFD_URL=https://x\nCTFD_TOKEN=t\n"), 0o600)
	r := run(t, legacy, "", "config", "show")
	if r.code != 0 || r.out["platform"] != "ctfd" {
		t.Fatalf("legacy config: %s %s", r.stdout, r.stderr)
	}
	if vals, _ := r.out["values"].(map[string]any); vals["CTFD_TOKEN"] != "***" {
		t.Fatalf("token not redacted: %s", r.stdout)
	}
	if r := run(t, legacy, "", "config", "migrate"); r.code != 0 {
		t.Fatalf("migrate: %s", r.stderr)
	}
	b, _ := os.ReadFile(filepath.Join(legacy, ".ctfx", "ctfd.env"))
	if !strings.HasPrefix(string(b), `CTFX_PLATFORM="ctfd"`) {
		t.Fatalf("migrated file: %s", b)
	}
}

func TestInitAutodetect(t *testing.T) {
	det := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html><head><title>Powered by CTFd</title></head></html>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer det.Close()
	root := workspace(t, "")
	os.RemoveAll(filepath.Join(root, ".ctfx"))
	r := run(t, root, "", "init", det.URL)
	if r.code != 0 || r.out["platform"] != "ctfd" || r.out["detected"] != true {
		t.Fatalf("autodetect: %d %s %s", r.code, r.stdout, r.stderr)
	}
	b, err := os.ReadFile(filepath.Join(root, ".ctfx", "ctfd.env"))
	if err != nil || !strings.Contains(string(b), `CTFD_URL="`+det.URL+`"`) || !strings.Contains(string(b), `CTFX_PLATFORM="ctfd"`) {
		t.Fatalf("written env: %v\n%s", err, b)
	}
}

func TestExecPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shebang plugins")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := workspace(t, "")
	src, _ := filepath.Abs("../../examples/drivers/ctfx-driver-example")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(root, ".ctfx", "drivers"), 0o755)
	os.WriteFile(filepath.Join(root, ".ctfx", "drivers", "ctfx-driver-example"), body, 0o755)
	os.WriteFile(filepath.Join(root, ".ctfx", "example.env"), []byte("EXAMPLE_FLAG=flag{py}\n"), 0o600)

	r := run(t, root, "", "platforms")
	if !strings.Contains(r.stdout, `"example"`) {
		t.Fatalf("plugin not listed: %s", r.stdout)
	}
	r = run(t, root, "", "chal", "ls")
	if r.code != 0 || r.out["total"] != float64(2) || r.out["platform"] != "example" {
		t.Fatalf("plugin ls: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = run(t, root, "flag{py}", "submit", "baby-rsa")
	if res, _ := r.out["result"].(map[string]any); r.code != 0 || res["status"] != "correct" || res["correct"] != true {
		t.Fatalf("plugin submit: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if r := run(t, root, "", "hint", "ls", "1"); r.code != ExitUnsupported {
		t.Fatalf("unadvertised op should exit 4: %d %s", r.code, r.stderr)
	}
	if r := run(t, root, "", "chal", "show", "404"); r.code != ExitRemote || !strings.Contains(r.stderr, "not_found") {
		t.Fatalf("plugin not_found: %d %s", r.code, r.stderr)
	}
}
