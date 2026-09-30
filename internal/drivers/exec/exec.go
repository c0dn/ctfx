// Package exec implements out-of-process drivers: any executable named
// ctfx-driver-<name> that speaks the JSON protocol described in
// docs/plugins.md. One process is spawned per operation.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// Protocol is the plugin protocol version sent on every call.
const Protocol = 1

// Prefix is the executable-name prefix for plugins.
const Prefix = "ctfx-driver-"

// Find locates the plugin executable for name: <root>/.ctfx/drivers first,
// then PATH. It returns "" when none exists.
func Find(root, name string) string {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return ""
	}
	dir := filepath.Join(root, config.Dir, "drivers")
	for _, cand := range []string{Prefix + name, name} {
		if p := filepath.Join(dir, cand); isExecutable(p) {
			return p
		}
	}
	if p, err := osexec.LookPath(Prefix + name); err == nil {
		return p
	}
	return ""
}

// List returns plugin names discoverable from root and PATH.
func List(root string) map[string]string {
	found := map[string]string{}
	add := func(dir string, bare bool) {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			n := e.Name()
			p := filepath.Join(dir, n)
			if e.IsDir() || !isExecutable(p) {
				continue
			}
			switch {
			case strings.HasPrefix(n, Prefix):
				n = strings.TrimPrefix(n, Prefix)
			case !bare:
				continue
			}
			n = strings.TrimSuffix(n, filepath.Ext(n))
			if _, ok := found[n]; !ok && n != "" {
				found[n] = p
			}
		}
	}
	add(filepath.Join(root, config.Dir, "drivers"), true)
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		add(d, false)
	}
	return found
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// Spec returns a driver spec for the plugin at path.
func Spec(name, path string) driver.Spec {
	up := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
	return driver.Spec{
		Name: name, DisplayName: name, Kind: "exec", Path: path,
		Description: "exec plugin " + path,
		Example:     fmt.Sprintf("# %s profile for ctfx (exec plugin)\nCTFX_PLATFORM=%q\n%s_URL=\"https://ctf.example\"\n# %s_TOKEN=\"\"\n", name, name, up, up),
		New: func(env *driver.Env) (ctf.Driver, error) {
			return &Driver{path: path, cfg: env.Config}, nil
		},
	}
}

// Driver proxies every operation to the plugin process.
type Driver struct {
	path string
	cfg  *config.Config

	once sync.Once
	caps ctf.Capabilities
	err  error
}

type request struct {
	Protocol int            `json:"protocol"`
	Op       string         `json:"op"`
	Config   requestConfig  `json:"config"`
	Args     map[string]any `json:"args"`
}

type requestConfig struct {
	Platform string            `json:"platform"`
	Profile  string            `json:"profile,omitempty"`
	Root     string            `json:"root"`
	Source   string            `json:"source"`
	Values   map[string]string `json:"values"`
}

type response struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

func (d *Driver) call(ctx context.Context, op string, args map[string]any, out any) error {
	if args == nil {
		args = map[string]any{}
	}
	in, err := json.Marshal(request{Protocol: Protocol, Op: op, Args: args, Config: requestConfig{
		Platform: d.cfg.Platform, Profile: d.cfg.Profile, Root: d.cfg.Root, Source: d.cfg.Source, Values: d.cfg.Values}})
	if err != nil {
		return err
	}
	cmd := osexec.CommandContext(ctx, d.path, op)
	cmd.Stdin = bytes.NewReader(in)
	cmd.Dir = d.cfg.Root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var resp response
	if json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp) != nil {
		detail := core.Truncate(stderr.String(), 400)
		if runErr != nil {
			return ctf.Errorf(ctf.KindRemote, "driver %s %s failed: %v: %s", filepath.Base(d.path), op, runErr, detail)
		}
		return ctf.Errorf(ctf.KindRemote, "driver %s %s returned invalid JSON: %s", filepath.Base(d.path), op, core.Truncate(stdout.String(), 200))
	}
	if resp.Error != nil {
		kind := ctf.Kind(resp.Error.Kind)
		switch kind {
		case ctf.KindUsage, ctf.KindConfig, ctf.KindAuth, ctf.KindUnsupported, ctf.KindNotFound, ctf.KindRemote:
		default:
			kind = ctf.KindRemote
		}
		return &ctf.Error{Kind: kind, Message: resp.Error.Message}
	}
	if runErr != nil {
		return ctf.Errorf(ctf.KindRemote, "driver %s %s exited with %v", filepath.Base(d.path), op, runErr)
	}
	if out != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return ctf.Errorf(ctf.KindRemote, "driver %s %s: bad result: %v", filepath.Base(d.path), op, err)
		}
	}
	return nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	d.once.Do(func() { d.err = d.call(context.Background(), "capabilities", nil, &d.caps) })
	return d.caps
}

// require fails fast with KindUnsupported when the plugin didn't advertise op.
func (d *Driver) require(ok bool, what string) error {
	if d.err != nil {
		return d.err
	}
	if !ok {
		return ctf.Errorf(ctf.KindUnsupported, "%s is not supported by driver %s", what, filepath.Base(d.path))
	}
	return nil
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	if err := d.require(d.Capabilities().Challenges, "listing challenges"); err != nil {
		return nil, err
	}
	var out []ctf.Challenge
	return out, d.call(ctx, "list_challenges", nil, &out)
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	if err := d.require(d.Capabilities().Challenges, "reading a challenge"); err != nil {
		return nil, err
	}
	var out ctf.Challenge
	return &out, d.call(ctx, "get_challenge", map[string]any{"id": id}, &out)
}

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	if err := d.require(d.Capabilities().Submit, "flag submission"); err != nil {
		return nil, err
	}
	var out ctf.SubmitResult
	if err := d.call(ctx, "submit", map[string]any{"id": id, "flag": flag}, &out); err != nil {
		return nil, err
	}
	if out.ChallengeID == "" {
		out.ChallengeID = id
	}
	out.Correct = out.Status == ctf.StatusCorrect
	return &out, nil
}

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	if err := d.require(d.Capabilities().Solves, "solve history"); err != nil {
		return nil, err
	}
	var out []ctf.Solve
	return out, d.call(ctx, "solves", nil, &out)
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	if err := d.require(d.Capabilities().Scoreboard, "scoreboard"); err != nil {
		return nil, err
	}
	var out ctf.Scoreboard
	return &out, d.call(ctx, "scoreboard", map[string]any{"limit": q.Limit, "offset": q.Offset, "division": q.Division}, &out)
}

func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	if err := d.require(d.Capabilities().Team, "team status"); err != nil {
		return nil, err
	}
	var out ctf.TeamStatus
	return &out, d.call(ctx, "team", nil, &out)
}

func (d *Driver) PrepareDownload(ctx context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	if err := d.require(d.Capabilities().Download, "file download"); err != nil {
		return nil, err
	}
	var out ctf.DownloadRequest
	if err := d.call(ctx, "prepare_download", map[string]any{"url": fileURL}, &out); err != nil {
		return nil, err
	}
	if out.URL == "" {
		out.URL = fileURL
	}
	return &out, nil
}

func (d *Driver) Hints(ctx context.Context, challengeID string) ([]ctf.Hint, error) {
	if err := d.require(d.Capabilities().Hints, "hints"); err != nil {
		return nil, err
	}
	var out []ctf.Hint
	return out, d.call(ctx, "hints", map[string]any{"challenge_id": challengeID}, &out)
}

func (d *Driver) UnlockHint(ctx context.Context, hintID string) (*ctf.Hint, error) {
	if err := d.require(d.Capabilities().UnlockHint, "hint unlock"); err != nil {
		return nil, err
	}
	var out ctf.Hint
	return &out, d.call(ctx, "unlock_hint", map[string]any{"hint_id": hintID}, &out)
}

func (d *Driver) Instance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	if err := d.require(d.Capabilities().Instances, "challenge instances"); err != nil {
		return nil, err
	}
	var out ctf.Instance
	return &out, d.call(ctx, "instance", map[string]any{"action": action, "challenge": challenge}, &out)
}
