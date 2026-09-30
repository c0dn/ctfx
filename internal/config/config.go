// Package config discovers the workspace, selects a profile, and merges
// env-file values with process environment overrides.
//
// Layout:
//
//	<root>/.ctfx/<profile>.env   profile files (gitignored; *.example ignored)
//	<root>/.ctfx/drivers/        optional workspace-local exec drivers
//	<root>/.opencode/ctf/<platform>.env   legacy ocws tool-pack config (read-only fallback)
//
// Keys keep the per-platform names the old tool packs used (CTFD_URL,
// RCTF_TEAM_TOKEN, ...). Get("URL") on a ctfd profile reads CTFD_URL and
// falls back to the generic CTFX_URL.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/c0dn/ctfx/pkg/ctf"
)

const (
	Dir       = ".ctfx"
	LegacyDir = ".opencode/ctf"
)

// Options are the caller's explicit selections (flags); empty means unset.
type Options struct {
	Dir      string // start directory; defaults to cwd
	Profile  string
	Platform string
}

// Config is the resolved configuration for one invocation.
type Config struct {
	Root     string            `json:"root"`
	Profile  string            `json:"profile,omitempty"`
	Platform string            `json:"platform"`
	Source   string            `json:"source"`
	Values   map[string]string `json:"-"`
}

// Prefix is the env-key prefix for the platform, eg "CTFD".
func (c *Config) Prefix() string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(c.Platform))
}

// Get reads <PREFIX>_<key>, then CTFX_<key>.
func (c *Config) Get(key string) string {
	if v := strings.TrimSpace(c.Values[c.Prefix()+"_"+key]); v != "" {
		return v
	}
	return strings.TrimSpace(c.Values["CTFX_"+key])
}

// Bool reads a boolean key; anything but 0/false/no/off is true.
func (c *Config) Bool(key string, def bool) bool {
	v := strings.ToLower(c.Get(key))
	if v == "" {
		return def
	}
	return !(v == "0" || v == "false" || v == "no" || v == "off")
}

// Redacted returns the platform-relevant values with secrets masked.
func (c *Config) Redacted() map[string]string {
	out := map[string]string{}
	for k, v := range c.Values {
		if !strings.HasPrefix(k, c.Prefix()+"_") && !strings.HasPrefix(k, "CTFX_") {
			continue
		}
		if IsSecretKey(k) && v != "" {
			v = "***"
		}
		out[k] = v
	}
	return out
}

// IsSecretKey reports whether a key name looks like a credential.
func IsSecretKey(k string) bool {
	k = strings.ToUpper(k)
	for _, s := range []string{"TOKEN", "COOKIE", "SESSION", "PASSWORD", "SECRET", "KEY", "QUICK_ACCESS_URL"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// FindRoot walks up from start looking for .ctfx/, then legacy .opencode/ctf/.
// It returns start itself when neither exists.
func FindRoot(start string) string {
	for _, marker := range []string{Dir, LegacyDir} {
		for cur := start; ; {
			if st, err := os.Stat(filepath.Join(cur, marker)); err == nil && st.IsDir() {
				return cur
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	return start
}

// Profiles lists profile names in <root>/.ctfx.
func Profiles(root string) []string {
	return envFiles(filepath.Join(root, Dir))
}

// LegacyProfiles lists platform names with a legacy .opencode/ctf/<p>.env.
func LegacyProfiles(root string) []string {
	return envFiles(filepath.Join(root, LegacyDir))
}

func envFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".env") {
			continue
		}
		names = append(names, strings.TrimSuffix(n, ".env"))
	}
	sort.Strings(names)
	return names
}

// Load resolves the configuration. known reports whether a platform name has a
// driver (built-in or exec) for the workspace root; builtin lists built-in
// names for env-only detection.
func Load(opts Options, known func(root, name string) bool, builtin []string) (*Config, error) {
	start := opts.Dir
	if start == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		start = wd
	}
	start, _ = filepath.Abs(start)
	root := FindRoot(start)
	if r := os.Getenv("CTFX_ROOT"); r != "" && opts.Dir == "" {
		root, _ = filepath.Abs(r)
	}

	profile := opts.Profile
	if profile == "" {
		profile = os.Getenv("CTFX_PROFILE")
	}

	cfg := &Config{Root: root, Values: map[string]string{}, Source: "environment"}
	file, err := pickFile(root, profile)
	if err != nil {
		return nil, err
	}
	if file != "" {
		vals, err := ParseEnvFile(file)
		if err != nil {
			return nil, err
		}
		cfg.Values = vals
		cfg.Source = file
		cfg.Profile = strings.TrimSuffix(filepath.Base(file), ".env")
	}
	platform := firstNonEmpty(opts.Platform, os.Getenv("CTFX_PLATFORM"), cfg.Values["CTFX_PLATFORM"])
	if platform == "" && cfg.Profile != "" && known(root, cfg.Profile) {
		platform = cfg.Profile
	}
	if platform == "" {
		var hits []string
		for _, b := range builtin {
			if os.Getenv(strings.ToUpper(b)+"_URL") != "" {
				hits = append(hits, b)
			}
		}
		if len(hits) == 1 {
			platform = hits[0]
		}
	}
	if platform == "" {
		return nil, ctf.Errorf(ctf.KindConfig,
			"no platform configured in %s: run `ctfx init <platform>` or set CTFX_PLATFORM", root)
	}
	if !known(root, platform) {
		return nil, ctf.Errorf(ctf.KindConfig,
			"unknown platform %q: no built-in driver and no ctfx-driver-%s executable found", platform, platform)
	}
	cfg.Platform = platform
	// Non-empty process env values override the file, like the old packs did.
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if v != "" && (strings.HasPrefix(k, cfg.Prefix()+"_") || strings.HasPrefix(k, "CTFX_")) {
			cfg.Values[k] = v
		}
	}
	return cfg, nil
}

func pickFile(root, profile string) (string, error) {
	dir := filepath.Join(root, Dir)
	legacy := filepath.Join(root, LegacyDir)
	if profile != "" {
		for _, p := range []string{filepath.Join(dir, profile+".env"), filepath.Join(legacy, profile+".env")} {
			if fileExists(p) {
				return p, nil
			}
		}
		return "", ctf.Errorf(ctf.KindConfig, "profile %q not found (expected %s)", profile, filepath.Join(dir, profile+".env"))
	}
	for _, d := range []string{dir, legacy} {
		names := envFiles(d)
		switch len(names) {
		case 0:
			continue
		case 1:
			return filepath.Join(d, names[0]+".env"), nil
		default:
			return "", ctf.Errorf(ctf.KindConfig,
				"multiple profiles in %s (%s): pass --profile or set CTFX_PROFILE", d, strings.Join(names, ", "))
		}
	}
	return "", nil
}

// ParseEnvFile reads KEY=value lines, ignoring blanks and # comments, and
// strips one layer of matching quotes.
func ParseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		vals[k] = v
	}
	return vals, sc.Err()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
