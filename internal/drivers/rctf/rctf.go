// Package rctf implements the rCTF driver (auth token or team-token login).
package rctf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

var Spec = driver.Spec{
	Name:        "rctf",
	DisplayName: "rCTF",
	Description: "rCTF with auth token or team token; per-team instancer, no hints",
	Kind:        "builtin",
	Example: `# rCTF profile for ctfx
CTFX_PLATFORM="rctf"
RCTF_URL="https://your-rctf-instance.example"
RCTF_VERIFY_SSL="true"
# The public scoreboard works with just RCTF_URL. Everything else needs exactly
# one of these:
# RCTF_AUTH_TOKEN=""   # sent as Authorization: Bearer
# RCTF_TEAM_TOKEN=""   # exchanged for an auth token via /api/v1/auth/login
`,
	New:    New,
	Detect: Detect,
}

// Detect recognizes an rCTF instance from its public leaderboard envelope.
func Detect(ctx context.Context, c *http.Client, rawURL string) (*driver.Detection, bool) {
	base, err := core.NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, false
	}
	resp, err := core.Do(ctx, c, core.Request{
		URL:     base + "/api/v1/leaderboard/now?limit=1&offset=0",
		Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil || resp.Status >= 500 {
		return nil, false
	}
	var env struct {
		Kind string `json:"kind"`
	}
	if resp.JSON(&env) && strings.HasPrefix(env.Kind, "good") {
		return &driver.Detection{BaseURL: base}, true
	}
	return nil, false
}

// Driver talks to one rCTF instance.
type Driver struct {
	ctf.Unsupported
	client    *http.Client
	base      string
	authToken string
	teamToken string

	once    sync.Once
	authErr error
}

// New builds an rCTF driver.
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	base, err := core.NormalizeBaseURL(c.Get("URL"))
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "RCTF_URL is missing or invalid; set it in %s or the environment", c.Source)
	}
	d := &Driver{client: env.Client, base: base, authToken: c.Get("AUTH_TOKEN"), teamToken: c.Get("TEAM_TOKEN")}
	if d.authToken != "" && d.teamToken != "" {
		return nil, ctf.Errorf(ctf.KindConfig, "rCTF config is ambiguous: set exactly one of RCTF_AUTH_TOKEN or RCTF_TEAM_TOKEN")
	}
	return d, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Team: true, Download: true, Instances: true}
}

type envelope struct {
	Kind    string          `json:"kind"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func isErrorKind(k string) bool { return strings.HasPrefix(k, "bad") || strings.HasPrefix(k, "error") }

func (d *Driver) raw(ctx context.Context, method, path string, body any, token string) (*core.Response, *envelope, error) {
	u, err := core.JoinURL(d.base+"/api/v1/", path)
	if err != nil {
		return nil, nil, err
	}
	h := map[string]string{"Accept": "application/json"}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	resp, err := core.Do(ctx, d.client, core.Request{Method: method, URL: u, Headers: h, JSON: body})
	if err != nil {
		return nil, nil, err
	}
	var env envelope
	if !resp.JSON(&env) {
		return resp, nil, nil
	}
	return resp, &env, nil
}

// token returns the auth token, exchanging the team token once if needed.
func (d *Driver) token(ctx context.Context) (string, error) {
	d.once.Do(func() {
		if d.authToken != "" || d.teamToken == "" {
			return
		}
		resp, env, err := d.raw(ctx, http.MethodPost, "auth/login", map[string]any{"teamToken": d.teamToken}, "")
		if err != nil {
			d.authErr = err
			return
		}
		var data struct {
			AuthToken string `json:"authToken"`
		}
		if env != nil && env.Kind == "goodLogin" && json.Unmarshal(env.Data, &data) == nil && data.AuthToken != "" {
			d.authToken = data.AuthToken
			return
		}
		msg := ""
		if env != nil {
			msg = env.Message
		}
		if resp.Status == 401 || msg == "" {
			d.authErr = ctf.Errorf(ctf.KindAuth, "rCTF login with RCTF_TEAM_TOKEN failed: %s", firstNonEmpty(msg, "HTTP "+strconv.Itoa(resp.Status)))
			return
		}
		d.authErr = ctf.Errorf(ctf.KindAuth, "rCTF login failed: %s", msg)
	})
	if d.authErr != nil {
		return "", d.authErr
	}
	return d.authToken, nil
}

func (d *Driver) authMissing() error {
	return ctf.Errorf(ctf.KindConfig, "rCTF authentication required: set RCTF_AUTH_TOKEN or RCTF_TEAM_TOKEN")
}

// api performs an authenticated (unless public) call and returns data.
func (d *Driver) api(ctx context.Context, method, path string, body any, public bool, out any) (*envelope, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" && !public {
		return nil, d.authMissing()
	}
	resp, env, err := d.raw(ctx, method, path, body, tok)
	if err != nil {
		return nil, err
	}
	msg := ""
	if env != nil {
		msg = firstNonEmpty(env.Message, env.Kind)
	}
	if resp.Status == 401 {
		hint := "check RCTF_AUTH_TOKEN"
		if d.teamToken != "" {
			hint = "check RCTF_TEAM_TOKEN"
		}
		return nil, ctf.Errorf(ctf.KindAuth, "rCTF authentication failed (%s): %s", msg, hint)
	}
	if resp.Status >= 400 {
		if env == nil {
			msg = core.Truncate(string(resp.Body), 200)
		}
		return nil, core.StatusError(resp.Status, "rCTF "+path, msg)
	}
	if env == nil {
		return nil, ctf.Errorf(ctf.KindRemote, "rCTF returned non-JSON for %s", path)
	}
	if isErrorKind(env.Kind) {
		return nil, ctf.Errorf(ctf.KindRemote, "rCTF %s failed: %s", path, msg)
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return nil, ctf.Errorf(ctf.KindRemote, "rCTF %s: unexpected data: %v", path, err)
		}
	}
	return env, nil
}

func points(c map[string]any) *float64 {
	if p := core.Num(c["points"]); p != nil {
		return p
	}
	p := core.Obj(c["points"])
	if v := core.Num(p["max"]); v != nil {
		return v
	}
	return core.Num(p["min"])
}

func (d *Driver) profile(ctx context.Context) (map[string]any, error) {
	var p map[string]any
	_, err := d.api(ctx, http.MethodGet, "users/me", nil, false, &p)
	return p, err
}

func (d *Driver) challenges(ctx context.Context) ([]map[string]any, map[string]bool, error) {
	var chals []map[string]any
	// Prefer /api/v2/challs: it is a superset of v1 and carries the per-team
	// instancer metadata (instancerLifetime). Fall back to v1 for forks that
	// only serve the older list endpoint.
	if _, err := d.api(ctx, http.MethodGet, "../v2/challs", nil, false, &chals); err != nil {
		if ctf.KindOf(err) != ctf.KindNotFound {
			return nil, nil, err
		}
		if _, err := d.api(ctx, http.MethodGet, "challs", nil, false, &chals); err != nil {
			return nil, nil, err
		}
	}
	p, err := d.profile(ctx)
	if err != nil {
		return nil, nil, err
	}
	solved := map[string]bool{}
	for _, s := range core.Arr(p["solves"]) {
		if id := core.Str(s); id != "" {
			solved[id] = true
			continue
		}
		o := core.Obj(s)
		for _, k := range []string{"id", "challengeId"} {
			if id := core.Str(o[k]); id != "" {
				solved[id] = true
			}
		}
	}
	return chals, solved, nil
}

func (d *Driver) mapChallenge(c map[string]any, solved map[string]bool) ctf.Challenge {
	ch := ctf.Challenge{
		ID:          core.Str(c["id"]),
		Name:        core.Str(c["name"]),
		Category:    core.Str(c["category"]),
		Author:      core.Str(c["author"]),
		Points:      points(c),
		Solves:      core.Int(c["solves"]),
		Description: core.Str(c["description"]),
	}
	ch.Solved = solved[ch.ID]
	for _, f := range core.Arr(c["files"]) {
		var name, raw string
		if s, ok := f.(string); ok {
			raw = s
		} else {
			o := core.Obj(f)
			name, raw = core.Str(o["name"]), core.Str(o["url"])
		}
		if raw == "" {
			continue
		}
		u, err := core.JoinURL(d.base, raw)
		if err != nil {
			continue
		}
		if name == "" {
			name = core.FilenameFromURL(u)
		}
		ch.Files = append(ch.Files, ctf.File{Name: core.SanitizeFilename(name), URL: u})
	}
	// v2 /challs marks per-team instancer challenges with a non-null lifetime.
	if c["instancerLifetime"] != nil {
		ch.Instance = &ctf.InstanceRef{Backend: "rctf", Slug: ch.ID}
		if ms := core.Num(c["instancerLifetime"]); ms != nil {
			if ch.Extra == nil {
				ch.Extra = map[string]any{}
			}
			ch.Extra["instance_lifetime_ms"] = int64(*ms)
		}
	}
	return ch
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	chals, solved, err := d.challenges(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ctf.Challenge, 0, len(chals))
	for _, c := range chals {
		ch := d.mapChallenge(c, solved)
		ch.Description, ch.Files = "", nil
		out = append(out, ch)
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

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	id = strings.TrimSpace(id)
	chals, solved, err := d.challenges(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range chals {
		if core.Str(c["id"]) == id {
			ch := d.mapChallenge(c, solved)
			return &ch, nil
		}
	}
	return nil, ctf.Errorf(ctf.KindNotFound, "rCTF challenge not found: %s", id)
}

var submitKinds = map[string]string{
	"goodFlag":                  ctf.StatusCorrect,
	"badFlag":                   ctf.StatusIncorrect,
	"badAlreadySolvedChallenge": ctf.StatusAlreadySolved,
	"badRateLimit":              ctf.StatusRateLimited,
	"badChallenge":              ctf.StatusBadChallenge,
	"badNotStarted":             ctf.StatusNotStarted,
	"badEnded":                  ctf.StatusEnded,
}

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	id = strings.TrimSpace(id)
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return nil, d.authMissing()
	}
	resp, env, err := d.raw(ctx, http.MethodPost, "challs/"+url.PathEscape(id)+"/submit", map[string]any{"flag": flag}, tok)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, core.StatusError(resp.Status, "rCTF submit", core.Truncate(string(resp.Body), 200))
	}
	if env.Kind == "badToken" || env.Kind == "badTokenVerification" {
		return nil, ctf.Errorf(ctf.KindAuth, "rCTF authentication failed: %s", env.Message)
	}
	res := &ctf.SubmitResult{ChallengeID: id, ResponseKind: env.Kind, Message: env.Message, HTTPStatus: resp.Status}
	res.Status = submitKinds[env.Kind]
	if res.Status == "" {
		res.Status = ctf.StatusError
	}
	res.Correct = res.Status == ctf.StatusCorrect
	return res, nil
}

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	p, err := d.profile(ctx)
	if err != nil {
		return nil, err
	}
	out := []ctf.Solve{}
	for _, s := range core.Arr(p["solves"]) {
		r := core.Obj(s)
		sv := ctf.Solve{ChallengeID: core.Str(r["id"]), Name: core.Str(r["name"]), Category: core.Str(r["category"]), Points: core.Num(r["points"])}
		if ms := core.Num(r["createdAt"]); ms != nil {
			sv.Date = time.UnixMilli(int64(*ms)).UTC().Format(time.RFC3339)
		}
		out = append(out, sv)
	}
	return out, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	v := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(q.Offset)}}
	if q.Division != "" {
		v.Set("division", q.Division)
	}
	var data map[string]any
	if _, err := d.api(ctx, http.MethodGet, "leaderboard/now?"+v.Encode(), nil, true, &data); err != nil {
		return nil, err
	}
	sb := &ctf.Scoreboard{Entries: []ctf.ScoreEntry{}}
	for i, e := range core.Arr(data["leaderboard"]) {
		r := core.Obj(e)
		sb.Entries = append(sb.Entries, ctf.ScoreEntry{Position: q.Offset + i + 1, AccountID: core.Str(r["id"]),
			AccountType: "team", Name: core.Str(r["name"]), Score: core.Deref(core.Num(r["score"]))})
	}
	sb.Total = len(sb.Entries)
	if t := core.Int(data["total"]); t != nil {
		sb.Total = *t
	}
	return sb, nil
}

func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	p, err := d.profile(ctx)
	if err != nil {
		return nil, err
	}
	acct := &ctf.Account{ID: core.Str(p["id"]), Name: core.Str(p["name"]), Email: core.Str(p["email"]),
		Score: core.Num(p["score"]), Place: core.Int(p["globalPlace"]),
		Extra: map[string]any{"division": p["division"], "division_place": p["divisionPlace"]}}
	ts := &ctf.TeamStatus{User: acct}
	team := *acct
	// Members are optional (email verification disabled instances 4xx here).
	tok, _ := d.token(ctx)
	resp, env, err := d.raw(ctx, http.MethodGet, "users/me/members", nil, tok)
	switch {
	case err != nil:
		ts.TeamError = err.Error()
	case env != nil && env.Kind == "goodMemberData":
		var ms []map[string]any
		_ = json.Unmarshal(env.Data, &ms)
		for _, m := range ms {
			team.Members = append(team.Members, ctf.Member{ID: core.Str(m["id"]), Name: core.Str(m["name"]), Email: core.Str(m["email"])})
		}
	case env != nil:
		ts.TeamError = firstNonEmpty(env.Message, env.Kind)
	default:
		ts.TeamError = "HTTP " + strconv.Itoa(resp.Status)
	}
	ts.Team = &team
	return ts, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func (d *Driver) PrepareDownload(ctx context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	u, err := core.JoinURL(d.base, fileURL)
	if err != nil {
		return nil, err
	}
	dr := &ctf.DownloadRequest{URL: u}
	if core.SameOrigin(u, d.base) {
		tok, err := d.token(ctx)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			dr.Headers = map[string]string{"Authorization": "Bearer " + tok}
		}
	}
	return dr, nil
}

// instanceEndpoint is one exposed connection from the rCTF instancer.
type instanceEndpoint struct {
	Kind  string `json:"kind"` // tcp, tcp-ssl, http, https, raw
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

// instanceStatus is the data payload of goodInstanceStatus.
type instanceStatus struct {
	Status               string             `json:"status"` // stopped, starting, running, stopping, errored
	TimeLeftMilliseconds *int64             `json:"timeLeftMilliseconds"`
	Endpoints            []instanceEndpoint `json:"endpoints"`
}

// instance drives FortID's per-team instancer, a service bolted onto standard
// rCTF at /api/v2/integrations/challs/:id/instance. The HTTP verb selects the
// action (GET status, PUT start, PATCH extend, DELETE stop); every verb returns
// the same goodInstanceStatus envelope.
func (d *Driver) Instance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	id := strings.TrimSpace(challenge)
	method := ""
	switch action {
	case ctf.InstanceStatus:
		method = http.MethodGet
	case ctf.InstanceStart:
		method = http.MethodPut
	case ctf.InstanceExtend:
		method = http.MethodPatch
	case ctf.InstanceStop:
		method = http.MethodDelete
	default:
		return nil, ctf.Errorf(ctf.KindUsage, "unknown instance action %q", action)
	}
	if id == "" {
		return nil, ctf.Errorf(ctf.KindUsage, "instance needs a challenge ID")
	}

	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return nil, d.authMissing()
	}

	var body any
	if method != http.MethodGet {
		body = map[string]any{}
	}
	resp, env, err := d.raw(ctx, method, "../v2/integrations/challs/"+url.PathEscape(id)+"/instance", body, tok)
	if err != nil {
		return nil, err
	}

	inst := &ctf.Instance{Challenge: id, Backend: "rctf", Action: action, HTTPStatus: resp.Status}
	if resp.Status == 401 {
		hint := "check RCTF_AUTH_TOKEN"
		if d.teamToken != "" {
			hint = "check RCTF_TEAM_TOKEN"
		}
		msg := ""
		if env != nil {
			msg = firstNonEmpty(env.Message, env.Kind)
		}
		return nil, ctf.Errorf(ctf.KindAuth, "rCTF authentication failed (%s): %s", msg, hint)
	}
	if env == nil {
		return nil, core.StatusError(resp.Status, "rCTF instance "+action, core.Truncate(string(resp.Body), 200))
	}

	// The instancer reports "not configured" as a badInstancerError. Treat a
	// status query on such a challenge as "no instance" rather than an error.
	if isErrorKind(env.Kind) {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(env.Data, &e)
		msg := firstNonEmpty(e.Message, env.Message, env.Kind)
		if action == ctf.InstanceStatus && strings.Contains(strings.ToLower(msg), "not configured") {
			inst.Status, inst.Message = "not_started", msg
			return inst, nil
		}
		inst.Status, inst.Message = "error", msg
		return inst, nil
	}

	var st instanceStatus
	if len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, &st); err != nil {
			return nil, ctf.Errorf(ctf.KindRemote, "rCTF instance %s: unexpected data: %v", action, err)
		}
	}
	if st.TimeLeftMilliseconds != nil {
		inst.Expires = time.Now().UTC().Add(time.Duration(*st.TimeLeftMilliseconds) * time.Millisecond).Format(time.RFC3339)
	}
	if ep := pickEndpoint(st.Endpoints); ep != nil {
		inst.Host = ep.Host
		if ep.Port != 0 {
			inst.Host = ep.Host + ":" + strconv.Itoa(ep.Port)
		}
		inst.Connect = connectFor(ep)
	}

	switch st.Status {
	case "stopped", "":
		switch action {
		case ctf.InstanceStop:
			inst.Status = "terminated"
		case ctf.InstanceStatus:
			inst.Status, inst.Message = "not_started", firstNonEmpty(inst.Message, "instance not started")
		default:
			// A start/extend that still reports stopped did not take effect.
			inst.Status = "stopped"
		}
	case "errored":
		inst.Status = "error"
		inst.Message = firstNonEmpty(inst.Message, "instancer reported an errored instance")
	default:
		// running, starting, stopping: report the real lifecycle state.
		inst.Status = st.Status
	}
	return inst, nil
}

// pickEndpoint chooses the most useful endpoint: the first with a host, but
// preferring one that carries a port (a concrete connect target).
func pickEndpoint(eps []instanceEndpoint) *instanceEndpoint {
	var fallback *instanceEndpoint
	for i := range eps {
		ep := &eps[i]
		if ep.Host == "" {
			continue
		}
		if ep.Port != 0 {
			return ep
		}
		if fallback == nil {
			fallback = ep
		}
	}
	return fallback
}

// connectFor builds a connection hint from an instancer endpoint.
func connectFor(ep *instanceEndpoint) *ctf.Connect {
	host := ep.Host
	if ep.Port != 0 {
		host = ep.Host + ":" + strconv.Itoa(ep.Port)
	}
	c := &ctf.Connect{Host: host, Command: ep.Text}
	switch ep.Kind {
	case "http":
		c.URL = "http://" + host
	case "https":
		c.URL = "https://" + host
	case "tcp-ssl":
		if c.Command == "" {
			c.Command = "openssl s_client -quiet -connect " + ep.Host + ":" + strconv.Itoa(ep.Port)
		}
	case "tcp", "raw", "":
		if c.Command == "" && ep.Port != 0 {
			c.Command = "nc " + ep.Host + " " + strconv.Itoa(ep.Port)
		}
	}
	return c
}
