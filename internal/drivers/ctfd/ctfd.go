// Package ctfd implements the CTFd driver: stock /api/v1 token or session
// auth, plus KubeCTF per-team instances via /api/kube_ctf/<slug>.
package ctfd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

var Spec = driver.Spec{
	Name:        "ctfd",
	DisplayName: "CTFd",
	Description: "CTFd with access-token or session-cookie auth; hints and KubeCTF instances",
	Kind:        "builtin",
	Example: `# CTFd profile for ctfx
CTFX_PLATFORM="ctfd"
CTFD_URL="https://your-ctfd-instance.example"
# Use either an access token (Settings -> Access Tokens) or a browser session cookie.
CTFD_TOKEN=""
# CTFD_SESSION_COOKIE=""   # value only, without "session="
# CTFD_CSRF_TOKEN=""       # needed by some session-auth POST routes (KubeCTF)
# CTFD_AUTH_MODE="auto"    # auto, token, or session
# CTFD_INSTANCE="kubectf"  # per-team instancer: kubectf (default), whale, owl, or chall-manager
CTFD_VERIFY_SSL="true"
`,
	New:    New,
	Detect: Detect,
}

// Detect recognizes a CTFd instance from its swagger doc or homepage markers.
func Detect(ctx context.Context, c *http.Client, rawURL string) (*driver.Detection, bool) {
	base, err := core.NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, false
	}
	if resp, err := core.Do(ctx, c, core.Request{URL: base + "/api/v1/swagger.json"}); err == nil &&
		resp.Status == 200 && strings.Contains(string(resp.Body), "CTFd") {
		return &driver.Detection{BaseURL: base}, true
	}
	if resp, err := core.Do(ctx, c, core.Request{URL: base}); err == nil {
		body := string(resp.Body)
		if strings.Contains(body, "CTFd") || strings.Contains(body, "/themes/core") {
			return &driver.Detection{BaseURL: base}, true
		}
	}
	return nil, false
}

type authMode string

const (
	authAuto    authMode = "auto"
	authToken   authMode = "token"
	authSession authMode = "session"
)

// Driver talks to one CTFd instance.
type Driver struct {
	ctf.Unsupported
	client   *http.Client
	base     string
	token    string
	session  string
	csrf     string
	mode     authMode
	instance string // "", kubectf, whale, owl, chall-manager
}

// New builds a CTFd driver from env.
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	base, err := core.NormalizeBaseURL(c.Get("URL"))
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFD_URL is missing or invalid; set it in %s or the environment", c.Source)
	}
	d := &Driver{
		client:  env.Client,
		base:    base,
		token:   c.Get("TOKEN"),
		session: firstNonEmpty(c.Get("SESSION_COOKIE"), c.Get("SESSION")),
		csrf:    c.Get("CSRF_TOKEN"),
	}
	d.session = strings.TrimPrefix(d.session, "session=")
	switch m := strings.ToLower(c.Get("AUTH_MODE")); m {
	case "", "auto":
		d.mode = authAuto
	case "token", "session":
		d.mode = authMode(m)
	default:
		return nil, ctf.Errorf(ctf.KindConfig, "invalid CTFD_AUTH_MODE %q: expected auto, token, or session", m)
	}
	if d.token == "" && d.session == "" {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFd needs CTFD_TOKEN or CTFD_SESSION_COOKIE")
	}
	switch inst := strings.ToLower(c.Get("INSTANCE")); inst {
	case "", "auto", "kubectf", "whale", "ctfd-whale", "owl", "ctfd-owl", "chall-manager", "ctfd-chall-manager":
		d.instance = strings.TrimPrefix(inst, "ctfd-")
	default:
		return nil, ctf.Errorf(ctf.KindConfig, "invalid CTFD_INSTANCE %q: expected kubectf, whale, owl, or chall-manager", inst)
	}
	return d, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Team: true,
		Download: true, Hints: true, UnlockHint: true, Instances: true}
}

func (d *Driver) resolveAuth(pluginRoute bool) (authMode, error) {
	switch d.mode {
	case authToken:
		if d.token == "" {
			return "", ctf.Errorf(ctf.KindConfig, "CTFD_AUTH_MODE=token but CTFD_TOKEN is not set")
		}
		return authToken, nil
	case authSession:
		if d.session == "" {
			return "", ctf.Errorf(ctf.KindConfig, "CTFD_AUTH_MODE=session but CTFD_SESSION_COOKIE is not set")
		}
		return authSession, nil
	}
	if pluginRoute && d.session != "" {
		return authSession, nil
	}
	if d.token != "" {
		return authToken, nil
	}
	return authSession, nil
}

func (d *Driver) authHint(m authMode) string {
	if m == authSession {
		return "check CTFD_SESSION_COOKIE and CTFD_CSRF_TOKEN"
	}
	return "check CTFD_TOKEN"
}

// call performs a request. plugin=true targets <base>/<path> instead of /api/v1.
func (d *Driver) call(ctx context.Context, method, path string, body any, plugin bool) (*core.Response, authMode, error) {
	mode, err := d.resolveAuth(plugin)
	if err != nil {
		return nil, "", err
	}
	root := d.base + "/api/v1/"
	if plugin {
		root = d.base + "/"
	}
	u, err := core.JoinURL(root, strings.TrimLeft(path, "/"))
	if err != nil {
		return nil, "", err
	}
	h := map[string]string{"Accept": "application/json"}
	if mode == authToken {
		h["Authorization"] = "Token " + d.token
	} else {
		h["Cookie"] = "session=" + d.session
		if d.csrf != "" && method != http.MethodGet && method != http.MethodHead {
			h["CSRF-Token"] = d.csrf
		}
	}
	// Stock CTFd only honors token auth when request.is_json is true, so the
	// JSON content type must be sent even on GETs (else /users/me and
	// solved_by_me break).
	if !plugin || mode == authToken || body != nil {
		h["Content-Type"] = "application/json"
	}
	resp, err := core.Do(ctx, d.client, core.Request{Method: method, URL: u, Headers: h, JSON: body})
	return resp, mode, err
}

type envelope struct {
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
	Meta    map[string]any  `json:"meta"`
	Message string          `json:"message"`
	Errors  any             `json:"errors"`
}

func (e *envelope) msg() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Errors != nil {
		b, _ := json.Marshal(e.Errors)
		return string(b)
	}
	return ""
}

// api calls /api/v1 and returns the decoded data; errors are classified.
func (d *Driver) api(ctx context.Context, method, path string, body, out any) (*envelope, error) {
	resp, mode, err := d.call(ctx, method, path, body, false)
	if err != nil {
		return nil, err
	}
	var env envelope
	parsed := resp.JSON(&env)
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "CTFd authentication failed: %s", d.authHint(mode))
	}
	if resp.Status >= 400 {
		m := env.msg()
		if !parsed {
			m = core.Truncate(string(resp.Body), 200)
		}
		return nil, core.StatusError(resp.Status, "CTFd "+path, m)
	}
	if !parsed {
		return nil, ctf.Errorf(ctf.KindRemote, "CTFd returned non-JSON for %s (wrong URL, or a login page?)", path)
	}
	if env.Success != nil && !*env.Success {
		return nil, ctf.Errorf(ctf.KindRemote, "CTFd %s failed: %s", path, env.msg())
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return nil, ctf.Errorf(ctf.KindRemote, "CTFd %s: unexpected data: %v", path, err)
		}
	}
	return &env, nil
}

func (d *Driver) mapChallenge(r map[string]any) ctf.Challenge {
	ch := ctf.Challenge{
		ID:          core.Str(r["id"]),
		Name:        core.Str(r["name"]),
		Category:    core.Str(r["category"]),
		Points:      core.Num(r["value"]),
		Solved:      r["solved_by_me"] == true,
		Solves:      core.Int(r["solves"]),
		Description: core.Str(r["description"]),
		Connection:  core.Str(r["connection_info"]),
	}
	extra := map[string]any{}
	for _, k := range []string{"type", "state", "max_attempts", "requirements", "template_name", "tags"} {
		if v, ok := r[k]; ok && v != nil {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		ch.Extra = extra
	}
	if slug := core.Str(r["template_name"]); slug != "" && r["type"] == "kubectf" {
		ch.Instance = &ctf.InstanceRef{Backend: "kubectf", Slug: slug}
	}
	for _, f := range core.Arr(r["files"]) {
		// Stock CTFd lists plain paths; some forks/plugins use {"location": ...}.
		raw := core.Str(f)
		if raw == "" {
			raw = core.Str(core.Obj(f)["location"])
		}
		if raw == "" {
			continue
		}
		u, err := core.JoinURL(d.base, raw)
		if err != nil {
			continue
		}
		ch.Files = append(ch.Files, ctf.File{Name: core.FilenameFromURL(u), URL: u})
	}
	ch.Hints = mapHints(core.Arr(r["hints"]))
	return ch
}

func mapHints(raw []any) []ctf.Hint {
	var out []ctf.Hint
	for _, h := range raw {
		r := core.Obj(h)
		hint := ctf.Hint{ID: core.Str(r["id"]), Title: core.Str(r["title"]), Cost: core.Deref(core.Num(r["cost"]))}
		if c, ok := r["content"].(string); ok {
			hint.Content = &c
		}
		hint.Locked = hint.Content == nil
		out = append(out, hint)
	}
	return out
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	var raw []map[string]any
	if _, err := d.api(ctx, http.MethodGet, "challenges", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ctf.Challenge, 0, len(raw))
	for _, r := range raw {
		out = append(out, d.mapChallenge(r))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if core.Deref(a.Points) != core.Deref(b.Points) {
			return core.Deref(a.Points) < core.Deref(b.Points)
		}
		return a.Name < b.Name
	})
	return out, nil
}

func numericID(id, what string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(id))
	if err != nil || n <= 0 {
		return 0, ctf.Errorf(ctf.KindUsage, "CTFd %s must be a positive integer, got %q", what, id)
	}
	return n, nil
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	n, err := numericID(id, "challenge ID")
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if _, err := d.api(ctx, http.MethodGet, fmt.Sprintf("challenges/%d", n), nil, &raw); err != nil {
		return nil, err
	}
	ch := d.mapChallenge(raw)
	if ch.ID == "" {
		ch.ID = strconv.Itoa(n)
	}
	return &ch, nil
}

var submitStatus = map[string]string{
	"correct":        ctf.StatusCorrect,
	"incorrect":      ctf.StatusIncorrect,
	"already_solved": ctf.StatusAlreadySolved,
	"ratelimited":    ctf.StatusRateLimited,
	"paused":         ctf.StatusNotStarted,
}

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	n, err := numericID(id, "challenge ID")
	if err != nil {
		return nil, err
	}
	resp, mode, err := d.call(ctx, http.MethodPost, "challenges/attempt", map[string]any{"challenge_id": n, "submission": flag}, false)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "CTFd authentication failed: %s", d.authHint(mode))
	}
	var env envelope
	if !resp.JSON(&env) {
		return nil, core.StatusError(resp.Status, "CTFd submit", core.Truncate(string(resp.Body), 200))
	}
	var data map[string]any
	_ = json.Unmarshal(env.Data, &data)
	raw := core.Str(data["status"])
	res := &ctf.SubmitResult{ChallengeID: strconv.Itoa(n), HTTPStatus: resp.Status, ResponseKind: raw,
		Message: firstNonEmpty(core.Str(data["message"]), env.msg())}
	switch {
	case submitStatus[raw] != "":
		res.Status = submitStatus[raw]
	case resp.Status == 429:
		res.Status = ctf.StatusRateLimited
	case resp.Status == 404:
		res.Status = ctf.StatusBadChallenge
	case resp.Status == 403:
		// CTFd returns 403 before start / after end / when paused.
		res.Status = ctf.StatusNotStarted
		if strings.Contains(strings.ToLower(res.Message), "ended") {
			res.Status = ctf.StatusEnded
		}
	default:
		res.Status = ctf.StatusError
	}
	res.Correct = res.Status == ctf.StatusCorrect
	return res, nil
}

// Solves prefers team solves (team mode) and falls back to the user's own,
// which is all user-mode CTFd has.
func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	var raw []map[string]any
	if _, err := d.api(ctx, http.MethodGet, "teams/me/solves", nil, &raw); err != nil {
		raw = nil // user mode or no team: the user endpoint reports real failures
		if _, err := d.api(ctx, http.MethodGet, "users/me/solves", nil, &raw); err != nil {
			return nil, err
		}
	}
	out := make([]ctf.Solve, 0, len(raw))
	for _, r := range raw {
		c := core.Obj(r["challenge"])
		out = append(out, ctf.Solve{
			ChallengeID: firstNonEmpty(core.Str(r["challenge_id"]), core.Str(c["id"])),
			Name:        firstNonEmpty(core.Str(c["name"]), core.Str(r["name"])),
			Category:    core.Str(c["category"]),
			Points:      core.Num(c["value"]),
			Date:        core.Str(r["date"]),
		})
	}
	return out, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	var raw []map[string]any
	if _, err := d.api(ctx, http.MethodGet, "scoreboard", nil, &raw); err != nil {
		return nil, err
	}
	sb := &ctf.Scoreboard{Total: len(raw)}
	for i, r := range raw {
		if q.Division != "" && !strings.EqualFold(core.Str(r["bracket_name"]), q.Division) {
			continue
		}
		e := ctf.ScoreEntry{
			Position:    i + 1,
			AccountID:   core.Str(r["account_id"]),
			AccountType: core.Str(r["account_type"]),
			Name:        core.Str(r["name"]),
			Score:       core.Deref(core.Num(r["score"])),
		}
		if p := core.Int(r["pos"]); p != nil {
			e.Position = *p
		}
		if b := core.Str(r["bracket_name"]); b != "" {
			e.Extra = map[string]any{"bracket": b}
		}
		sb.Entries = append(sb.Entries, e)
	}
	if q.Division != "" {
		sb.Total = len(sb.Entries)
	}
	sb.Entries = window(sb.Entries, q)
	return sb, nil
}

func window(e []ctf.ScoreEntry, q ctf.ScoreboardQuery) []ctf.ScoreEntry {
	if q.Offset >= len(e) {
		return []ctf.ScoreEntry{}
	}
	e = e[q.Offset:]
	if q.Limit > 0 && q.Limit < len(e) {
		e = e[:q.Limit]
	}
	return e
}

func account(r map[string]any) *ctf.Account {
	a := &ctf.Account{ID: core.Str(r["id"]), Name: core.Str(r["name"]), Email: core.Str(r["email"]),
		Score: core.Num(r["score"]), Place: placeOf(r["place"])}
	for _, m := range core.Arr(r["members"]) {
		switch mv := m.(type) {
		case map[string]any:
			a.Members = append(a.Members, ctf.Member{ID: core.Str(mv["id"]), Name: core.Str(mv["name"]), Score: core.Num(mv["score"])})
		default:
			a.Members = append(a.Members, ctf.Member{ID: core.Str(mv)})
		}
	}
	return a
}

// placeOf parses CTFd places like "3rd" as well as plain numbers.
func placeOf(v any) *int {
	if i := core.Int(v); i != nil {
		return i
	}
	s := strings.TrimRight(core.Str(v), "stndrdth")
	if n, err := strconv.Atoi(s); err == nil {
		return &n
	}
	return nil
}

func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	var user map[string]any
	if _, err := d.api(ctx, http.MethodGet, "users/me", nil, &user); err != nil {
		return nil, err
	}
	ts := &ctf.TeamStatus{User: account(user)}
	if tid := core.Str(user["team_id"]); tid != "" && tid != "0" {
		ts.User.Extra = map[string]any{"team_id": tid}
		var team map[string]any
		if _, err := d.api(ctx, http.MethodGet, "teams/me", nil, &team); err != nil {
			ts.TeamError = err.Error()
		} else {
			ts.Team = account(team)
		}
	}
	return ts, nil
}

func (d *Driver) PrepareDownload(_ context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	u, err := core.JoinURL(d.base, fileURL)
	if err != nil {
		return nil, err
	}
	dr := &ctf.DownloadRequest{URL: u}
	if core.SameOrigin(u, d.base) {
		if d.token != "" && d.mode != authSession {
			dr.Headers = map[string]string{"Authorization": "Token " + d.token}
		} else if d.session != "" {
			dr.Headers = map[string]string{"Cookie": "session=" + d.session}
		}
	}
	return dr, nil
}

func (d *Driver) Hints(ctx context.Context, challengeID string) ([]ctf.Hint, error) {
	ch, err := d.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if ch.Hints == nil {
		return []ctf.Hint{}, nil
	}
	return ch.Hints, nil
}

func (d *Driver) UnlockHint(ctx context.Context, hintID string) (*ctf.Hint, error) {
	n, err := numericID(hintID, "hint ID")
	if err != nil {
		return nil, err
	}
	if _, err := d.api(ctx, http.MethodPost, "unlocks", map[string]any{"target": n, "type": "hints"}, nil); err != nil {
		return nil, err
	}
	var raw map[string]any
	if _, err := d.api(ctx, http.MethodGet, fmt.Sprintf("hints/%d", n), nil, &raw); err != nil {
		return nil, err
	}
	hs := mapHints([]any{raw})
	h := hs[0]
	if h.ID == "" {
		h.ID = strconv.Itoa(n)
	}
	return &h, nil
}

// Instance routes to the configured per-team instance backend. KubeCTF is the
// default; whale, owl, and chall-manager are common CTFd instancer plugins.
func (d *Driver) Instance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	switch action {
	case ctf.InstanceStatus, ctf.InstanceStart, ctf.InstanceExtend, ctf.InstanceStop:
	default:
		return nil, ctf.Errorf(ctf.KindUsage, "unknown instance action %q", action)
	}
	switch d.instance {
	case "whale", "owl", "chall-manager":
		return d.pluginInstance(ctx, action, d.instance, challenge)
	}
	return d.kubeInstance(ctx, action, challenge)
}

// pluginInstance drives the whale / owl / chall-manager instancer plugins,
// which key on the numeric challenge ID. Response field names differ between
// plugins and versions, so connection details are extracted best-effort and
// the raw payload is preserved in Message when no host is found. (Route/param
// shapes are from the plugins' READMEs; verify against your instance.)
func (d *Driver) pluginInstance(ctx context.Context, action, backend, challenge string) (*ctf.Instance, error) {
	id, err := numericID(challenge, "challenge ID")
	if err != nil {
		return nil, err
	}
	var path string
	var pluginRoot bool
	switch backend {
	case "whale":
		path, pluginRoot = "plugins/ctfd-whale/container", false
	case "chall-manager":
		path, pluginRoot = "plugins/ctfd-chall-manager/instance", false
	case "owl":
		path, pluginRoot = "plugins/ctfd-owl/container", true
	}
	method := map[string]string{
		ctf.InstanceStatus: http.MethodGet,
		ctf.InstanceStart:  http.MethodPost,
		ctf.InstanceExtend: http.MethodPatch,
		ctf.InstanceStop:   http.MethodDelete,
	}[action]

	// chall-manager uses camelCase challengeId; whale/owl use challenge_id.
	param := "challenge_id"
	if backend == "chall-manager" {
		param = "challengeId"
	}
	var body any
	if method == http.MethodGet {
		path += "?" + param + "=" + strconv.Itoa(id)
	} else {
		body = map[string]any{param: id}
	}

	resp, mode, err := d.call(ctx, method, path, body, pluginRoot)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "CTFd authentication failed: %s", d.authHint(mode))
	}
	var payload map[string]any
	resp.JSON(&payload)
	data := payload
	if inner := core.Obj(payload["data"]); len(inner) > 0 {
		data = inner
	}
	inst := &ctf.Instance{Challenge: challenge, Backend: backend, Action: action, HTTPStatus: resp.Status}
	inst.Message = firstNonEmpty(core.Str(payload["message"]), core.Str(payload["error"]))
	inst.Expires = firstNonEmpty(core.Str(data["expires"]), core.Str(data["end_time"]), core.Str(data["remaining_time"]))
	host := firstNonEmpty(core.Str(data["host"]), core.Str(data["domain"]), core.Str(data["lan_domain"]), core.Str(data["ip"]), core.Str(data["remote"]), core.Str(data["connect"]))
	if port := core.Str(data["port"]); host != "" && port != "" && !strings.Contains(host, ":") {
		host += ":" + port
	}
	inst.Host = host
	ok := resp.Status < 400
	switch {
	case action == ctf.InstanceStatus && (resp.Status == 404 || (ok && host == "" && inst.Message == "")):
		inst.Status, inst.Message = "not_started", firstNonEmpty(inst.Message, "instance not started")
	case !ok:
		inst.Status = "error"
		if inst.Message == "" {
			inst.Message = core.Truncate(string(resp.Body), 300)
		}
	default:
		inst.Status = map[string]string{ctf.InstanceStatus: "running", ctf.InstanceStart: "started", ctf.InstanceExtend: "extended", ctf.InstanceStop: "terminated"}[action]
		// Surface the raw fields when we could not identify a host.
		if host == "" && inst.Message == "" && action != ctf.InstanceStop && len(data) > 0 {
			inst.Message = core.Truncate(string(resp.Body), 300)
		}
	}
	if host != "" {
		inst.Connect = &ctf.Connect{Host: host}
		if h, p, found := strings.Cut(host, ":"); found {
			inst.Connect.Command = "nc " + h + " " + p
		} else {
			inst.Connect.URL = "http://" + host
		}
	}
	return inst, nil
}

func (d *Driver) kubeInstance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	slug := strings.TrimSpace(challenge)
	if _, err := strconv.Atoi(slug); err == nil {
		ch, err := d.GetChallenge(ctx, slug)
		if err != nil {
			return nil, err
		}
		if ch.Instance == nil {
			return nil, ctf.Errorf(ctf.KindUnsupported, "challenge %s (%s) has no KubeCTF instance", slug, ch.Name)
		}
		slug = ch.Instance.Slug
	}
	if slug == "" {
		return nil, ctf.Errorf(ctf.KindUsage, "instance needs a challenge ID or KubeCTF slug")
	}
	method, body := http.MethodPost, map[string]any(nil)
	switch action {
	case ctf.InstanceStatus:
		method = http.MethodGet
	case ctf.InstanceStart:
		body = map[string]any{"action": "create"}
	case ctf.InstanceExtend:
		body = map[string]any{"action": "extend"}
	case ctf.InstanceStop:
		body = map[string]any{"action": "terminate"}
	default:
		return nil, ctf.Errorf(ctf.KindUsage, "unknown instance action %q", action)
	}
	var b any
	if body != nil {
		b = body
	}
	resp, mode, err := d.call(ctx, method, "api/kube_ctf/"+url.PathEscape(slug), b, true)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "CTFd authentication failed: %s", d.authHint(mode))
	}
	var payload map[string]any
	resp.JSON(&payload)
	inst := &ctf.Instance{Challenge: slug, Backend: "kubectf", Action: action, HTTPStatus: resp.Status}
	dep := core.Obj(payload["deployment"])
	inst.Host, inst.Expires, inst.Owner = core.Str(dep["host"]), core.Str(dep["expires"]), core.Str(dep["owner"])
	ok := resp.Status < 400
	inst.Message = firstNonEmpty(core.Str(payload["message"]), core.Str(payload["error"]))
	switch {
	case action == ctf.InstanceStatus && resp.Status == 404:
		inst.Status, inst.Message = "not_started", firstNonEmpty(inst.Message, "instance not started")
	case !ok || (action != ctf.InstanceStop && inst.Host == ""):
		inst.Status = "error"
		if inst.Message == "" {
			inst.Message = core.Truncate(string(resp.Body), 200)
		}
	case action == ctf.InstanceStatus:
		inst.Status = "running"
	case action == ctf.InstanceStart:
		inst.Status = "started"
	case action == ctf.InstanceExtend:
		inst.Status = "extended"
	case action == ctf.InstanceStop:
		inst.Status = "terminated"
	}
	if inst.Host != "" {
		inst.Connect = &ctf.Connect{Host: inst.Host, URL: "https://" + inst.Host}
		if strings.Contains(inst.Host, "pwn") {
			inst.Connect.Command = "openssl s_client -quiet -connect " + inst.Host + ":443"
		}
	}
	return inst, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
