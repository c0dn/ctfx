package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/c0dn/ctfx/pkg/ctf"
)

var builtin = []string{"ctfd", "rctf"}

func known(_, name string) bool {
	for _, b := range builtin {
		if b == name {
			return true
		}
	}
	return false
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"CTFX_PLATFORM", "CTFX_PROFILE", "CTFX_ROOT", "CTFX_URL", "CTFD_URL", "CTFD_TOKEN", "RCTF_URL"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.env")
	write(t, p, "# c\nA=\"x y\"\nexport B='z'\n\nC = plain\nnoequals\n")
	v, err := ParseEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if v["A"] != "x y" || v["B"] != "z" || v["C"] != "plain" || len(v) != 3 {
		t.Fatalf("got %v", v)
	}
}

func TestProfileFromCtfxDirWalksUp(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	write(t, filepath.Join(root, ".ctfx/ctfd.env"), "CTFD_URL=https://a\nCTFD_TOKEN=file\n")
	sub := filepath.Join(root, "challenges/pwn/x")
	os.MkdirAll(sub, 0o755)
	t.Setenv("CTFD_TOKEN", "env")
	cfg, err := Load(Options{Dir: sub}, known, builtin)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Root != root || cfg.Platform != "ctfd" || cfg.Profile != "ctfd" {
		t.Fatalf("got %+v", cfg)
	}
	if cfg.Get("TOKEN") != "env" || cfg.Get("URL") != "https://a" {
		t.Fatalf("env override: %v", cfg.Values)
	}
	if cfg.Redacted()["CTFD_TOKEN"] != "***" {
		t.Fatal("token not redacted")
	}
}

func TestNamedProfileNeedsPlatformKey(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	write(t, filepath.Join(root, ".ctfx/finals.env"), "CTFX_PLATFORM=rctf\nRCTF_URL=https://r\n")
	write(t, filepath.Join(root, ".ctfx/quals.env"), "CTFX_PLATFORM=ctfd\nCTFD_URL=https://q\n")
	if _, err := Load(Options{Dir: root}, known, builtin); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("expected ambiguity error, got %v", err)
	}
	cfg, err := Load(Options{Dir: root, Profile: "finals"}, known, builtin)
	if err != nil || cfg.Platform != "rctf" || cfg.Get("URL") != "https://r" {
		t.Fatalf("got %+v %v", cfg, err)
	}
	t.Setenv("CTFX_PROFILE", "quals")
	cfg, err = Load(Options{Dir: root}, known, builtin)
	if err != nil || cfg.Platform != "ctfd" {
		t.Fatalf("got %+v %v", cfg, err)
	}
}

func TestLegacyFallback(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	write(t, filepath.Join(root, ".opencode/ctf/rctf.env"), "RCTF_URL=https://b\n")
	write(t, filepath.Join(root, ".opencode/ctf/rctf.env.example"), "ignored")
	cfg, err := Load(Options{Dir: root}, known, builtin)
	if err != nil || cfg.Platform != "rctf" || cfg.Get("URL") != "https://b" {
		t.Fatalf("got %+v %v", cfg, err)
	}
}

func TestEnvOnlyDetection(t *testing.T) {
	clearEnv(t)
	root := t.TempDir()
	if _, err := Load(Options{Dir: root}, known, builtin); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("expected config error, got %v", err)
	}
	t.Setenv("RCTF_URL", "https://r")
	cfg, err := Load(Options{Dir: root}, known, builtin)
	if err != nil || cfg.Platform != "rctf" || cfg.Source != "environment" {
		t.Fatalf("got %+v %v", cfg, err)
	}
	if _, err := Load(Options{Dir: root, Platform: "nope"}, known, builtin); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("unknown platform should be config error: %v", err)
	}
}

func TestGenericFallbackKey(t *testing.T) {
	c := &Config{Platform: "my-ctf", Values: map[string]string{"CTFX_URL": "g", "MY_CTF_TOKEN": "t", "CTFX_VERIFY_SSL": "false"}}
	if c.Get("URL") != "g" || c.Get("TOKEN") != "t" || c.Bool("VERIFY_SSL", true) {
		t.Fatal("generic lookup failed")
	}
}
