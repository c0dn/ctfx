package hitcon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// Instancer kinds seen at HITCON CTF 2026.
//
//	hostname    nella17/hostname-instancer (Flask). POST /create token=... sets a
//	            signed session cookie and redirects to /, which shows the
//	            instance (host:port, created/stop times). POST /stop with that
//	            cookie stops it. GET / without the cookie shows nothing, so
//	            status needs the cookie saved by an earlier start. One instance
//	            per team; reachable only from the creating IP. (nsa, sitepreview)
//	calc        POST /api/start token=... -> {team,host?,port,expires_at} or
//	            {"error":...} (403 bad token, 409 busy, 503). No status/stop.
//	vulcreator  GET /api/team (X-Team-Token) -> {current_attempt,instances:[id]},
//	            GET /api/instances/<id> -> {status,name,screenshot_status}.
//	            Starting needs a Windows .exe upload (10 attempts per team), so
//	            only status is offered here.
const (
	kindHostname   = "hostname"
	kindCalc       = "calc"
	kindVulcreator = "vulcreator"
)

type instancerConf struct {
	Kind string
	URL  string // base URL, no trailing slash
}

// knownHosts maps an instancer host prefix to its kind. Any other
// *.chal.hitconctf.com link introduced as "Instancer:" is assumed hostname.
var knownHosts = map[string]string{
	"calc":        kindCalc,
	"vulcreator":  kindVulcreator,
	"nsa":         kindHostname,
	"sitepreview": kindHostname,
}

// parseInstancers reads HITCON_INSTANCERS: "id=kind@url;id=kind@url".
func parseInstancers(s string) (map[string]instancerConf, error) {
	out := map[string]instancerConf{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, rest, ok := strings.Cut(part, "=")
		kind, u, ok2 := strings.Cut(rest, "@")
		kind = strings.ToLower(strings.TrimSpace(kind))
		if !ok || !ok2 || (kind != kindHostname && kind != kindCalc && kind != kindVulcreator) {
			return nil, ctf.Errorf(ctf.KindConfig, "HITCON_INSTANCERS entry %q: want <id>=<hostname|calc|vulcreator>@<url>", part)
		}
		base, err := core.NormalizeBaseURL(strings.TrimSpace(u))
		if err != nil {
			return nil, ctf.Errorf(ctf.KindConfig, "HITCON_INSTANCERS entry %q: bad URL", part)
		}
		out[strings.TrimSpace(id)] = instancerConf{Kind: kind, URL: base}
	}
	return out, nil
}

var chalHostRe = regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.chal\.hitconctf\.com\b`)

// instancerFor picks the instancer for a challenge: explicit config first, then
// a known *.chal.hitconctf.com host in the description, then an "Instancer:" link.
func (d *Driver) instancerFor(id, description string) (instancerConf, bool) {
	if ic, ok := d.instancers[id]; ok {
		return ic, true
	}
	for _, m := range chalHostRe.FindAllStringSubmatch(description, -1) {
		if kind, ok := knownHosts[strings.ToLower(m[1])]; ok {
			return instancerConf{Kind: kind, URL: strings.TrimRight(strings.ToLower(m[0]), "/")}, true
		}
	}
	if m := instRe.FindStringSubmatch(description); m != nil {
		if hm := chalHostRe.FindString(m[1]); hm != "" {
			return instancerConf{Kind: kindHostname, URL: strings.ToLower(hm)}, true
		}
	}
	return instancerConf{}, false
}

// resolveInstancer maps a challenge ID, name or instancer host prefix to an
// instancer. Explicit config needs no scoreboard call.
func (d *Driver) resolveInstancer(ctx context.Context, arg string) (string, instancerConf, error) {
	arg = strings.TrimSpace(arg)
	if ic, ok := d.instancers[arg]; ok {
		return arg, ic, nil
	}
	list, err := d.raw(ctx)
	if err != nil {
		return "", instancerConf{}, err
	}
	for _, match := range []func(rawChallenge) bool{
		func(r rawChallenge) bool { return strconv.Itoa(r.ID) == arg },
		func(r rawChallenge) bool { return strings.EqualFold(r.Name, arg) },
		func(r rawChallenge) bool {
			ic, ok := d.instancerFor(strconv.Itoa(r.ID), r.Description)
			return ok && strings.Contains(ic.URL, "://"+strings.ToLower(arg)+".")
		},
	} {
		for _, r := range list {
			if !match(r) {
				continue
			}
			id := strconv.Itoa(r.ID)
			ic, ok := d.instancerFor(id, r.Description)
			if !ok {
				return id, instancerConf{}, ctf.Errorf(ctf.KindUnsupported, "HITCON challenge %s (%s) has no known instancer; set HITCON_INSTANCERS", id, r.Name)
			}
			return id, ic, nil
		}
	}
	return "", instancerConf{}, ctf.Errorf(ctf.KindNotFound, "HITCON challenge %q not found", arg)
}

func (d *Driver) Instance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	switch action {
	case ctf.InstanceStatus, ctf.InstanceStart, ctf.InstanceStop, ctf.InstanceExtend:
	default:
		return nil, ctf.Errorf(ctf.KindUsage, "unknown instance action %q", action)
	}
	id, ic, err := d.resolveInstancer(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if d.teamToken == "" {
		return nil, ctf.Errorf(ctf.KindConfig, "HITCON instancers need HITCON_TEAM_TOKEN (shown on /team/)")
	}
	inst := &ctf.Instance{Challenge: id, Backend: ic.Kind, Action: action}
	switch ic.Kind {
	case kindHostname:
		err = d.hostnameInstance(ctx, ic, inst)
	case kindCalc:
		err = d.calcInstance(ctx, ic, inst)
	case kindVulcreator:
		err = d.vulcreatorInstance(ctx, ic, inst)
	}
	if err != nil {
		return nil, err
	}
	return d.redact(inst), nil
}

// redact keeps the team token out of anything printed.
func (d *Driver) redact(inst *ctf.Instance) *ctf.Instance {
	r := strings.NewReplacer(d.teamToken, "<team-token>")
	inst.Message = r.Replace(inst.Message)
	if inst.Connect != nil {
		inst.Connect.URL = r.Replace(inst.Connect.URL)
		inst.Connect.Command = r.Replace(inst.Connect.Command)
	}
	return inst
}

func (d *Driver) instDo(ctx context.Context, req core.Request) (*core.Response, error) {
	resp, err := core.Do(ctx, d.inst, req)
	if err != nil {
		// Never echo a URL or error that might carry the token.
		return nil, ctf.Errorf(ctf.KindRemote, "%s", strings.ReplaceAll(err.Error(), d.teamToken, "<team-token>"))
	}
	return resp, nil
}

// --- hostname-instancer -------------------------------------------------------

var (
	codeRe     = regexp.MustCompile(`(?s)Your instance:.*?<code>(.*?)</code>`)
	hrefRe     = regexp.MustCompile(`(?s)Your instance:.*?<a href="([^"]+)"`)
	instBlock  = regexp.MustCompile(`(?s)Your instance:(.*?)</p>`)
	fmtTimeRe  = regexp.MustCompile(`fmt\.format\((\d+)\)`)
	hostPortRe = regexp.MustCompile(`[A-Za-z0-9.-]+:\d+`)
)

func (d *Driver) hostnameInstance(ctx context.Context, ic instancerConf, inst *ctf.Instance) error {
	store := d.cookieStore()
	cookie := store.get(ic.URL)
	page := func(method, path, body string) (*core.Response, error) {
		h := map[string]string{"Accept": "text/html"}
		if cookie != "" {
			h["Cookie"] = cookie
		}
		if body != "" {
			h["Content-Type"] = "application/x-www-form-urlencoded"
		}
		req := core.Request{Method: method, URL: ic.URL + path, Headers: h}
		if body != "" {
			req.Body = strings.NewReader(body)
		}
		resp, err := d.instDo(ctx, req)
		if err != nil {
			return nil, err
		}
		if c := sessionFrom(resp); c != "" {
			cookie = c
			store.put(ic.URL, c)
		}
		return resp, nil
	}
	switch inst.Action {
	case ctf.InstanceExtend:
		return ctf.Errorf(ctf.KindUnsupported, "this instancer (%s) cannot extend; stop and start again", ic.URL)
	case ctf.InstanceStart:
		resp, err := page(http.MethodPost, "/create", url.Values{"token": {d.teamToken}}.Encode())
		if err != nil {
			return err
		}
		inst.HTTPStatus = resp.Status
		if body := string(resp.Body); resp.Status < 300 || resp.Status >= 400 {
			// A 200 here is an error page ("Invalid token", "<pre>Failed ...").
			msg := stripTags(body)
			if strings.Contains(strings.ToLower(msg), "invalid token") {
				return ctf.Errorf(ctf.KindAuth, "instancer rejected HITCON_TEAM_TOKEN")
			}
			if resp.Status >= 500 {
				return ctf.Errorf(ctf.KindRemote, "instancer %s answered %d (overloaded?); try again", ic.URL, resp.Status)
			}
			inst.Status, inst.Message = "error", core.Truncate(msg, 300)
			return nil
		}
	case ctf.InstanceStop:
		if cookie == "" {
			return ctf.Errorf(ctf.KindUsage, "no saved instancer session for %s: ctfx can only stop an instance it started (the instancer has no token-based stop)", ic.URL)
		}
		resp, err := page(http.MethodPost, "/stop", "")
		if err != nil {
			return err
		}
		inst.HTTPStatus = resp.Status
		if resp.Status >= 400 {
			return core.StatusError(resp.Status, "instancer stop", core.Truncate(stripTags(string(resp.Body)), 200))
		}
	case ctf.InstanceStatus:
		if cookie == "" {
			inst.Status = "unknown"
			inst.Message = "no saved instancer session, so status is unknown. `ctfx instance start` attaches to the team's existing instance if there is one (the instancer allows one per team) and creates one otherwise"
			return nil
		}
	}
	resp, err := page(http.MethodGet, "/", "")
	if err != nil {
		return err
	}
	if inst.HTTPStatus == 0 {
		inst.HTTPStatus = resp.Status
	}
	if resp.Status >= 400 {
		return ctf.Errorf(ctf.KindRemote, "instancer %s answered %d", ic.URL, resp.Status)
	}
	parseHostnamePage(string(resp.Body), inst)
	if inst.Action == ctf.InstanceStop && inst.Status == "not_started" {
		inst.Status, inst.Message = "stopped", "instance stopped"
	}
	return nil
}

// parseHostnamePage fills inst from the instancer's index page.
func parseHostnamePage(body string, inst *ctf.Instance) {
	if !strings.Contains(body, "Your instance:") {
		inst.Status, inst.Message = "not_started", "no instance for this session"
		return
	}
	inst.Status = "running"
	var target string
	if m := hrefRe.FindStringSubmatch(body); m != nil {
		target = m[1]
	} else if m := codeRe.FindStringSubmatch(body); m != nil {
		target = stripTags(m[1])
	} else if m := instBlock.FindStringSubmatch(body); m != nil {
		target = stripTags(m[1])
	}
	c := &ctf.Connect{}
	if u, err := url.Parse(target); err == nil && strings.Contains(target, "://") {
		c.URL, c.Host = target, u.Host
	} else if strings.HasPrefix(target, "nc ") {
		c.Command = target
		c.Host = hostPortRe.FindString(target)
	} else {
		c.Host = hostPortRe.FindString(target)
		if c.Host == "" {
			c.Host = target
		}
	}
	if block := instBlock.FindString(body); strings.Contains(strings.ToLower(block), "player") || strings.Contains(strings.ToLower(body), "basic auth") {
		inst.Message = "HTTP Basic auth: player:<team-token>"
		if c.URL == "" && c.Host != "" {
			c.URL = "http://" + c.Host + "/"
		}
	}
	inst.Host, inst.Connect = c.Host, c
	if ts := fmtTimeRe.FindAllStringSubmatch(body, -1); len(ts) >= 2 {
		if ms, err := strconv.ParseInt(ts[1][1], 10, 64); err == nil {
			inst.Expires = time.UnixMilli(ms).UTC().Format(time.RFC3339)
		}
	}
}

func sessionFrom(resp *core.Response) string {
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(sc); err == nil && c.Name == "session" {
			if c.Value == "" || c.MaxAge < 0 {
				return ""
			}
			return "session=" + c.Value
		}
	}
	return ""
}

// --- calc --------------------------------------------------------------------

func (d *Driver) calcInstance(ctx context.Context, ic instancerConf, inst *ctf.Instance) error {
	if inst.Action != ctf.InstanceStart {
		return ctf.Errorf(ctf.KindUnsupported, "the calc instancer only supports start (instances expire on their own; no status/stop API)")
	}
	resp, err := d.instDo(ctx, core.Request{
		Method:  http.MethodPost,
		URL:     ic.URL + "/api/start",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
		Body:    strings.NewReader(url.Values{"token": {d.teamToken}}.Encode()),
	})
	if err != nil {
		return err
	}
	inst.HTTPStatus = resp.Status
	var body struct {
		Team      string   `json:"team"`
		Host      string   `json:"host"`
		Port      any      `json:"port"`
		ExpiresAt *float64 `json:"expires_at"`
		Error     string   `json:"error"`
	}
	ok := resp.JSON(&body)
	switch {
	case resp.Status == 403:
		return ctf.Errorf(ctf.KindAuth, "calc instancer rejected HITCON_TEAM_TOKEN: %s", body.Error)
	case resp.Status == 409 || resp.Status == 503 || resp.Status == 429:
		inst.Status = "busy"
		inst.Message = firstNonEmpty(body.Error, http.StatusText(resp.Status)) + " (retry later)"
		return nil
	case resp.Status >= 300 || !ok:
		return ctf.Errorf(ctf.KindRemote, "calc instancer answered %d: %s", resp.Status, firstNonEmpty(body.Error, core.Truncate(string(resp.Body), 160)))
	}
	host := body.Host
	if host == "" {
		u, _ := url.Parse(ic.URL)
		host = u.Hostname()
	}
	port := core.Str(body.Port)
	inst.Status, inst.Owner = "running", body.Team
	inst.Host = host + ":" + port
	inst.Connect = &ctf.Connect{Host: inst.Host, URL: "http://" + inst.Host + "/"}
	if body.ExpiresAt != nil {
		inst.Expires = time.Unix(int64(*body.ExpiresAt), 0).UTC().Format(time.RFC3339)
	}
	return nil
}

// --- vulcreator --------------------------------------------------------------

func (d *Driver) vulcreatorInstance(ctx context.Context, ic instancerConf, inst *ctf.Instance) error {
	if inst.Action != ctf.InstanceStatus {
		return ctf.Errorf(ctf.KindUnsupported, "vulcreator instances start by uploading a Windows .exe (10 attempts per team); use the portal at %s or POST %s/api/instance (multipart team_token, executable)", ic.URL, ic.URL)
	}
	get := func(path string, out any) (int, error) {
		resp, err := d.instDo(ctx, core.Request{URL: ic.URL + "/api" + path, Headers: map[string]string{"X-Team-Token": d.teamToken, "Accept": "application/json"}})
		if err != nil {
			return 0, err
		}
		if resp.Status == 403 {
			return resp.Status, ctf.Errorf(ctf.KindAuth, "vulcreator rejected HITCON_TEAM_TOKEN")
		}
		if resp.Status >= 300 || !resp.JSON(out) {
			return resp.Status, ctf.Errorf(ctf.KindRemote, "vulcreator %s answered %d: %s", path, resp.Status, core.Truncate(string(resp.Body), 160))
		}
		return resp.Status, nil
	}
	var team struct {
		CurrentAttempt int   `json:"current_attempt"`
		Instances      []any `json:"instances"`
	}
	st, err := get("/team", &team)
	if err != nil {
		return err
	}
	inst.HTTPStatus = st
	if len(team.Instances) == 0 {
		inst.Status = "not_started"
		inst.Message = fmt.Sprintf("no instances; %d of 10 attempts used", team.CurrentAttempt)
		return nil
	}
	var lines []string
	latest := ""
	for _, raw := range team.Instances {
		id := core.Str(raw)
		var det struct {
			Status           string `json:"status"`
			Name             string `json:"name"`
			ScreenshotStatus string `json:"screenshot_status"`
		}
		if _, err := get("/instances/"+url.PathEscape(id), &det); err != nil {
			lines = append(lines, id+": "+err.Error())
			continue
		}
		if latest == "" {
			latest = det.Status
		}
		lines = append(lines, fmt.Sprintf("%s: %s (screenshot %s)", id, det.Status, firstNonEmpty(det.ScreenshotStatus, "pending")))
	}
	inst.Status = firstNonEmpty(latest, "unknown")
	inst.Message = fmt.Sprintf("%d of 10 attempts used; %s; screenshots at %s/api/instances/<id>/screenshot (X-Team-Token)",
		team.CurrentAttempt, strings.Join(lines, "; "), ic.URL)
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// --- instancer session store -------------------------------------------------

// cookieStore persists hostname-instancer session cookies in
// <root>/.ctfx/state/hitcon-instancers.json (0600, gitignored), so status and
// stop work across ctfx runs. With no workspace root it is memory-only.
type cookieStore struct {
	mu   sync.Mutex
	path string
	m    map[string]string
}

func (d *Driver) cookieStore() *cookieStore {
	if d.store == nil {
		s := &cookieStore{m: map[string]string{}}
		if d.root != "" {
			s.path = filepath.Join(d.root, ".ctfx", "state", "hitcon-instancers.json")
			if b, err := os.ReadFile(s.path); err == nil {
				_ = json.Unmarshal(b, &s.m)
			}
		}
		d.store = s
	}
	return d.store
}

func (s *cookieStore) get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}

func (s *cookieStore) put(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[k] == v {
		return
	}
	s.m[k] = v
	if s.path == "" {
		return
	}
	dir := filepath.Dir(s.path)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	gi := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gi); err != nil {
		_ = os.WriteFile(gi, []byte("# ctfx runtime state holds session cookies\n*\n"), 0o600)
	}
	if b, err := json.Marshal(s.m); err == nil {
		_ = os.WriteFile(s.path, b, 0o600)
	}
}
