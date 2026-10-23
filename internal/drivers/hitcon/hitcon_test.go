package hitcon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

const (
	testSession = "sess-abc"
	testToken   = "team-token-xyz"
)

// Recorded shapes from ctf2026.hitcon.org (values shortened, no secrets).
const challengeData = `[
 {"id":5,"name":"You Got Calc'd?","description":"Just pwn it -> http://calc.chal.hitconctf.com","category":"🍊","score":500,"author":"🍊","solved_times":0,"solved":false,"hint":null,"is_opened":true,"type":"jeopardy","koh_score":null},
 {"id":4,"name":"Night Shift Archive","description":"Your instance runs a private D-Bus service.\n\nInstancer: http://nsa.chal.hitconctf.com/\n\nThis is a blackbox challenge.","category":"misc","score":500,"author":"nella17","solved_times":0,"solved":false,"hint":null,"is_opened":true,"type":"jeopardy","koh_score":null},
 {"id":6,"name":"mathclipse","description":"Where mathematics meets the abyss.\n\nnc mathclipse.chal.hitconctf.com 16767\n\n[mathclipse-7c2a.tar.gz](https://ctf2026attach.hitconctf.com/25e7/mathclipse-7c2a.tar.gz)","category":"misc","score":360,"author":"x","solved_times":7,"solved":false,"hint":[{"content":"look closer","public_time":1792770000.0}],"is_opened":true,"type":"jeopardy","koh_score":null},
 {"id":1,"name":"Welcome","description":"**Welcome**","category":"welcome","score":50,"author":"","solved_times":325,"solved":true,"hint":null,"is_opened":true,"type":"jeopardy","koh_score":null},
 {"id":12,"name":"FastColl","description":"[challenge_link](http://fastcoll.chal.hitconctf.com/)\n\n[fastcoll.tar.gz](https://ctf2026attach.hitconctf.com/2db0/fastcoll.tar.gz)","category":"Crypto","score":500,"author":"y","solved_times":0,"solved":false,"hint":null,"is_opened":true,"type":"jeopardy","koh_score":null}
]`

const teamPage = `<script>window.__SITE_CONFIG__ = { teamId: 922, contestStartTime: 1792764000.0 };</script>
<div id="content" class="container"> <div class="col-lg-8 offset-lg-2"> <h4>n0l3rain</h4> <hr>
<div class="row"> <div class="col-lg-2">Country:</div> <div class="col-lg-10">Singapore <img src="/static/flags/sg.gif"></div> </div>
<div class="row"> <div class="col-lg-2">Rank:</div> <div class="col-lg-10">288/1073</div> </div>
<div class="row"> <div class="col-lg-2">Score:</div> <div class="col-lg-10">50</div> </div>
<div class="row"> <div class="col-lg-2">Token:</div> <div class="col-lg-10"><code>` + testToken + `</code></div> </div>`

type fake struct {
	t          *testing.T
	submit     func(w http.ResponseWriter, r *http.Request)
	submitHits int
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionid")
	if err != nil || c.Value != testSession {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"detail":"login required"}`))
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /dashboard/challenge_data":
		w.Write([]byte(challengeData))
	case "GET /dashboard/":
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf-cookie", Path: "/"})
		w.Write([]byte(`<input type="hidden" name="csrfmiddlewaretoken" value="masked">`))
	case "POST /dashboard/submit_flag":
		f.submitHits++
		cc, _ := r.Cookie("csrftoken")
		if cc == nil || r.Header.Get("X-CSRFToken") != cc.Value || r.Header.Get("Origin") == "" {
			w.WriteHeader(403)
			w.Write([]byte("<h1>Forbidden (403)</h1><p>CSRF verification failed.</p>"))
			return
		}
		r.ParseForm()
		if r.PostForm.Get("id") != "1" {
			f.t.Errorf("submit id = %q", r.PostForm.Get("id"))
		}
		w.Header().Set("Content-Type", "application/json")
		f.submit(w, r)
	case "GET /dashboard/scoreboard_data":
		w.Write([]byte(`{"teamstat":[{"id":785,"name":"TeamH4C","score":784,"country_name":"South Korea","last_submit_time":1.0,"solved_challenge":[17,1,6]},
			{"id":922,"name":"n0l3rain","score":50,"country_name":"Singapore","last_submit_time":2.0,"solved_challenge":[1]}],"challenges":{},"last_update":3.0}`))
	case "GET /team/":
		w.Write([]byte(teamPage))
	default:
		w.WriteHeader(404)
	}
}

func newTest(t *testing.T, vals map[string]string) (*Driver, *fake) {
	t.Helper()
	f := &fake{t: t, submit: func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"result": "duplicated", "id": 1}`)) }}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	v := map[string]string{"HITCON_URL": srv.URL, "HITCON_SESSIONID": testSession, "HITCON_TEAM_TOKEN": testToken}
	for k, x := range vals {
		v[k] = x
	}
	cfg := &config.Config{Platform: "hitcon", Values: v}
	d, err := newDriver(cfg.Get, srv.Client(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return d, f
}

func TestNewValidation(t *testing.T) {
	cfg := &config.Config{Platform: "hitcon", Values: map[string]string{}}
	if _, err := New(&driver.Env{Config: cfg, Client: http.DefaultClient}); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("missing URL: %v", err)
	}
	cfg.Values = map[string]string{"HITCON_URL": "https://ctf2026.hitcon.org", "HITCON_INSTANCERS": "4=bogus@http://x"}
	if _, err := New(&driver.Env{Config: cfg, Client: http.DefaultClient}); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("bad instancer kind: %v", err)
	}
	cfg.Values = map[string]string{"HITCON_URL": "https://ctf2026.hitcon.org"}
	d, err := New(&driver.Env{Config: cfg, Client: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("missing sessionid should be a config error before any request: %v", err)
	}
}

func TestDetect(t *testing.T) {
	det, ok := Detect(context.Background(), nil, "https://ctf2026.hitcon.org/dashboard/#4")
	if !ok || det.BaseURL != "https://ctf2026.hitcon.org" {
		t.Fatalf("detect = %+v %v", det, ok)
	}
	if _, ok := Detect(context.Background(), nil, "https://ctf.example.org"); ok {
		t.Fatal("detected a non-HITCON host")
	}
}

func TestAuthError(t *testing.T) {
	d, _ := newTest(t, map[string]string{"HITCON_SESSIONID": "wrong"})
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("want auth error, got %v", err)
	}
}

func TestListAndParse(t *testing.T) {
	d, _ := newTest(t, nil)
	list, err := d.ListChallenges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 5 || list[0].ID != "1" || !list[0].Solved {
		t.Fatalf("list not sorted by id or missing solved: %+v", list[0])
	}
	by := map[string]ctf.Challenge{}
	for _, c := range list {
		by[c.ID] = c
	}
	m := by["6"]
	if m.Connection != "nc mathclipse.chal.hitconctf.com 16767" {
		t.Errorf("connection = %q", m.Connection)
	}
	if len(m.Files) != 1 || m.Files[0].Name != "mathclipse-7c2a.tar.gz" || !strings.HasPrefix(m.Files[0].URL, "https://ctf2026attach") {
		t.Errorf("files = %+v", m.Files)
	}
	if len(m.Hints) != 1 || *m.Hints[0].Content != "look closer" || m.Hints[0].Locked {
		t.Errorf("hints = %+v", m.Hints)
	}
	if by["4"].Instance == nil || by["4"].Instance.Backend != kindHostname || by["4"].Extra["instancer"] != "http://nsa.chal.hitconctf.com" {
		t.Errorf("nsa instancer = %+v %v", by["4"].Instance, by["4"].Extra["instancer"])
	}
	if by["5"].Instance == nil || by["5"].Instance.Backend != kindCalc {
		t.Errorf("calc instancer = %+v", by["5"].Instance)
	}
	fc := by["12"]
	if fc.Instance != nil || len(fc.Files) != 1 || fc.Connection != "http://fastcoll.chal.hitconctf.com/" {
		t.Errorf("fastcoll = inst %+v files %+v conn %q", fc.Instance, fc.Files, fc.Connection)
	}
	if _, err := d.GetChallenge(context.Background(), "99"); ctf.KindOf(err) != ctf.KindNotFound {
		t.Errorf("unknown id: %v", err)
	}
}

func TestSubmitVerdicts(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{200, `{"result": "duplicated", "id": 1}`, ctf.StatusAlreadySolved},
		{200, `{"result": "wrong", "id": 1}`, ctf.StatusIncorrect},
		{200, `{"result": "correct", "id": 1}`, ctf.StatusCorrect},
		{429, `{"detail": "Too fast. Wait a moment."}`, ctf.StatusRateLimited},
		{403, `{"detail": "The contest is not running."}`, ctf.StatusNotStarted},
	}
	for _, tc := range cases {
		d, f := newTest(t, nil)
		f.submit = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }
		res, err := d.Submit(context.Background(), "1", " hitcon{x} ")
		if err != nil {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if res.Status != tc.want || res.Correct != (tc.want == ctf.StatusCorrect) {
			t.Errorf("%s: got %+v", tc.body, res)
		}
	}
}

func TestSubmitWithConfiguredCSRF(t *testing.T) {
	d, _ := newTest(t, map[string]string{"HITCON_CSRFTOKEN": "stale"})
	// A configured but stale cookie is replaced by the server's Set-Cookie.
	res, err := d.Submit(context.Background(), "1", "x")
	if err != nil || res.Status != ctf.StatusAlreadySolved {
		t.Fatalf("got %+v %v", res, err)
	}
	if _, err := d.Submit(context.Background(), "abc", "x"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("non-numeric id: %v", err)
	}
}

func TestTeamAndScoreboard(t *testing.T) {
	d, _ := newTest(t, nil)
	ts, err := d.Team(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tm := ts.Team
	if tm.ID != "922" || tm.Name != "n0l3rain" || *tm.Score != 50 || *tm.Place != 288 || tm.Extra["country"] != "Singapore" {
		t.Fatalf("team = %+v", tm)
	}
	for _, v := range tm.Extra {
		if s, ok := v.(string); ok && strings.Contains(s, testToken) {
			t.Fatal("team token leaked into team output")
		}
	}
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Offset: 1, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Total != 2 || len(sb.Entries) != 1 || sb.Entries[0].Position != 2 || sb.Entries[0].AccountID != "922" {
		t.Fatalf("scoreboard = %+v", sb)
	}
	solves, err := d.Solves(context.Background())
	if err != nil || len(solves) != 1 || solves[0].ChallengeID != "1" {
		t.Fatalf("solves = %+v %v", solves, err)
	}
}

func TestPrepareDownload(t *testing.T) {
	d, _ := newTest(t, nil)
	dr, _ := d.PrepareDownload(context.Background(), "https://ctf2026attach.hitconctf.com/a/b.tar.gz")
	if dr.Headers != nil {
		t.Fatal("session cookie sent to a third-party host")
	}
	dr, _ = d.PrepareDownload(context.Background(), "/static/chall/x.zip")
	if dr.URL != d.base+"/static/chall/x.zip" || dr.Headers["Cookie"] != "sessionid="+testSession {
		t.Fatalf("same-origin download = %+v", dr)
	}
}

// --- instancers --------------------------------------------------------------

// hostnameServer mimics nella17/hostname-instancer.
func hostnameServer(t *testing.T, running *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		authed := c != nil && c.Value == "s1"
		switch r.Method + " " + r.URL.Path {
		case "POST /create":
			r.ParseForm()
			if r.PostForm.Get("token") != testToken {
				w.Write([]byte("<b>Invalid token</b>"))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
			*running = true
			http.Redirect(w, r, "/", http.StatusFound)
		case "POST /stop":
			if authed {
				*running = false
			}
			http.Redirect(w, r, "/", http.StatusFound)
		case "GET /":
			if authed && *running {
				io.WriteString(w, `<p>
                Your instance: nsa<br>
                    <code>abcd1234.nsa.chal.hitconctf.com:30922</code>
            </p>
            <script>
                document.getElementById('created').textContent = fmt.format(1792765000000);
                document.getElementById('stop').textContent = fmt.format(1792765900000);
            </script>`)
				return
			}
			io.WriteString(w, `<form action="/create" method="POST"></form><p>Instances will be stopped in 900 seconds</p>`)
		}
	}))
}

func TestHostnameInstancerLifecycle(t *testing.T) {
	running := false
	srv := hostnameServer(t, &running)
	defer srv.Close()
	root := t.TempDir()
	d, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "4=hostname@" + srv.URL})
	d.root = root
	ctx := context.Background()

	inst, err := d.Instance(ctx, ctf.InstanceStatus, "4")
	if err != nil || inst.Status != "unknown" {
		t.Fatalf("status without session = %+v %v", inst, err)
	}
	if _, err := d.Instance(ctx, ctf.InstanceStop, "4"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("stop without session must refuse: %v", err)
	}
	inst, err = d.Instance(ctx, ctf.InstanceStart, "4")
	if err != nil {
		t.Fatal(err)
	}
	if inst.Status != "running" || inst.Host != "abcd1234.nsa.chal.hitconctf.com:30922" || inst.Expires != "2026-10-23T14:31:40Z" {
		t.Fatalf("start = %+v", inst)
	}
	// Session persisted 0600 under .ctfx/state and picked up by a fresh driver.
	p := filepath.Join(root, ".ctfx", "state", "hitcon-instancers.json")
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}
	d2, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "4=hostname@" + srv.URL})
	d2.root = root
	if inst, err = d2.Instance(ctx, ctf.InstanceStatus, "4"); err != nil || inst.Status != "running" {
		t.Fatalf("status after restart = %+v %v", inst, err)
	}
	if _, err := d2.Instance(ctx, ctf.InstanceExtend, "4"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Fatalf("extend: %v", err)
	}
	if inst, err = d2.Instance(ctx, ctf.InstanceStop, "4"); err != nil || inst.Status != "stopped" || running {
		t.Fatalf("stop = %+v %v running=%v", inst, err, running)
	}
}

func TestHostnameBadToken(t *testing.T) {
	running := false
	srv := hostnameServer(t, &running)
	defer srv.Close()
	d, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "4=hostname@" + srv.URL, "HITCON_TEAM_TOKEN": "nope"})
	if _, err := d.Instance(context.Background(), ctf.InstanceStart, "4"); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("want auth error: %v", err)
	}
}

func TestCalcInstancer(t *testing.T) {
	reply := func(w http.ResponseWriter) {}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.URL.Path != "/api/start" || r.PostForm.Get("token") != testToken {
			w.WriteHeader(403)
			w.Write([]byte(`{"error": "Invalid team token"}`))
			return
		}
		reply(w)
	}))
	defer srv.Close()
	d, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "5=calc@" + srv.URL})
	ctx := context.Background()

	reply = func(w http.ResponseWriter) { w.WriteHeader(409); w.Write([]byte(`{"error": "Instances are busy"}`)) }
	inst, err := d.Instance(ctx, ctf.InstanceStart, "5")
	if err != nil || inst.Status != "busy" || !strings.Contains(inst.Message, "Instances are busy") {
		t.Fatalf("busy = %+v %v", inst, err)
	}
	reply = func(w http.ResponseWriter) {
		w.Write([]byte(`{"team": "n0l3rain", "port": 31337, "expires_at": 1792766000}`))
	}
	inst, err = d.Instance(ctx, ctf.InstanceStart, "5")
	u, _ := url.Parse(srv.URL)
	if err != nil || inst.Status != "running" || inst.Host != u.Hostname()+":31337" || inst.Owner != "n0l3rain" || inst.Expires == "" {
		t.Fatalf("start = %+v %v", inst, err)
	}
	if _, err := d.Instance(ctx, ctf.InstanceStatus, "5"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Fatalf("status: %v", err)
	}
}

func TestVulcreatorStatus(t *testing.T) {
	instances := `[]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Team-Token") != testToken {
			w.WriteHeader(403)
			w.Write([]byte(`{"detail":"Bad token :/"}`))
			return
		}
		switch r.URL.Path {
		case "/api/team":
			w.Write([]byte(`{"current_attempt":1,"instances":` + instances + `}`))
		case "/api/instances/j1":
			w.Write([]byte(`{"status":"running","name":"vm-1","screenshot_status":"pending"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "7=vulcreator@" + srv.URL})
	ctx := context.Background()
	inst, err := d.Instance(ctx, ctf.InstanceStatus, "7")
	if err != nil || inst.Status != "not_started" {
		t.Fatalf("empty = %+v %v", inst, err)
	}
	instances = `["j1"]`
	inst, err = d.Instance(ctx, ctf.InstanceStatus, "7")
	if err != nil || inst.Status != "running" || !strings.Contains(inst.Message, "j1: running") {
		t.Fatalf("status = %+v %v", inst, err)
	}
	if _, err := d.Instance(ctx, ctf.InstanceStart, "7"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Fatalf("start: %v", err)
	}
	bad, _ := newTest(t, map[string]string{"HITCON_INSTANCERS": "7=vulcreator@" + srv.URL, "HITCON_TEAM_TOKEN": "nope"})
	if _, err := bad.Instance(ctx, ctf.InstanceStatus, "7"); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("bad token: %v", err)
	}
}

func TestInstanceResolveByNameAndHost(t *testing.T) {
	d, _ := newTest(t, nil)
	for _, arg := range []string{"4", "Night Shift Archive", "nsa"} {
		id, ic, err := d.resolveInstancer(context.Background(), arg)
		if err != nil || id != "4" || ic.Kind != kindHostname {
			t.Errorf("%q -> %s %+v %v", arg, id, ic, err)
		}
	}
	if _, _, err := d.resolveInstancer(context.Background(), "6"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Errorf("no instancer: %v", err)
	}
}

func TestRedactToken(t *testing.T) {
	d, _ := newTest(t, nil)
	inst := d.redact(&ctf.Instance{Message: "auth player:" + testToken, Connect: &ctf.Connect{URL: "http://player:" + testToken + "@h/"}})
	if strings.Contains(inst.Message+inst.Connect.URL, testToken) {
		t.Fatalf("token not redacted: %+v", inst)
	}
}
