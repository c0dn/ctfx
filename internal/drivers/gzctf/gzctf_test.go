package gzctf

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

type fake struct {
	logins    int32
	polls     int32
	pending   int32  // FlagSubmitted responses before the verdict
	verdict   string // JSON AnswerResult
	submitErr string // status + body override for the submit POST
	priv      *ecdh.PrivateKey
	gotFlag   string
	gotPass   string
	container string // current instanceEntry, "" when none
}

func open(priv *ecdh.PrivateKey, b64 string) string {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	if len(raw) < 44 {
		return "<bad>"
	}
	pub, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return "<bad>"
	}
	shared, _ := priv.ECDH(pub)
	key := sha256.Sum256(shared)
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, raw[32:44], raw[44:], nil)
	if err != nil {
		return "<bad>"
	}
	return string(pt)
}

func (f *fake) decode(s string) string {
	if f.priv == nil {
		return s
	}
	return open(f.priv, s)
}

func (f *fake) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		route := r.Method + " " + r.URL.Path
		switch route {
		case "GET /api/Config":
			pk := "null"
			if f.priv != nil {
				pk = `"` + base64.StdEncoding.EncodeToString(f.priv.PublicKey().Bytes()) + `"`
			}
			w.Write([]byte(`{"title":"GZ","slogan":"Hack","apiPublicKey":` + pk + `,"portMapping":"Default","defaultLifetime":120}`))
			return
		case "POST /api/Account/LogIn":
			atomic.AddInt32(&f.logins, 1)
			var m map[string]string
			json.Unmarshal(body, &m)
			f.gotPass = f.decode(m["password"])
			if m["userName"] != "alice" || f.gotPass != "pw" {
				w.WriteHeader(401)
				w.Write([]byte(`{"title":"Incorrect username or password","status":401}`))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "GZCTF_Token", Value: "chunks-2"})
			http.SetCookie(w, &http.Cookie{Name: "GZCTF_TokenC1", Value: "aa"})
			http.SetCookie(w, &http.Cookie{Name: "GZCTF_TokenC2", Value: "bb"})
			return
		case "GET /api/Game/7/Scoreboard":
			w.Write([]byte(`{"items":[
				{"id":2,"name":"B","divisionId":1,"score":50,"rank":2,"divisionRank":1,"solvedChallenges":[]},
				{"id":1,"name":"A","divisionId":2,"score":90,"rank":1,"divisionRank":1,"solvedChallenges":[{"id":11}]},
				{"id":3,"name":"C","divisionId":1,"score":10,"rank":3,"divisionRank":2,"solvedChallenges":[]}],
				"divisions":[{"id":1,"name":"Students"},{"id":2,"name":"Open"}]}`))
			return
		}
		ck := r.Header.Get("Cookie")
		if ck != "GZCTF_Token=tok" && ck != "GZCTF_Token=chunks-2; GZCTF_TokenC1=aa; GZCTF_TokenC2=bb" {
			w.WriteHeader(401)
			w.Write([]byte(`{"title":"Unauthorized","status":401}`))
			return
		}
		switch route {
		case "GET /api/Game/7/Details":
			w.Write([]byte(`{"challenges":{"Web":[{"id":12,"title":"b","category":"Web","score":300,"solved":1},
				{"id":11,"title":"a","category":"Web","score":100,"solved":4}],
				"Pwn":[{"id":13,"title":"c","category":"Pwn","score":500,"solved":0,"deadline":"2026-10-01T00:00:00Z"}]},
				"rank":{"id":5,"name":"team5","score":100,"rank":3,"solvedChallenges":[{"id":11,"score":100,"type":"FirstBlood","time":"2026-09-30T01:02:03Z"}]},
				"teamToken":"x"}`))
		case "GET /api/Game/7/Challenges/11":
			w.Write([]byte(`{"id":11,"title":"a","content":"desc","category":"Web","hints":["h1","h2"],"score":100,
				"type":"StaticAttachment","limit":0,"attempts":2,
				"context":{"url":"/assets/abc/a.zip","fileSize":10}}`))
		case "GET /api/Game/7/Challenges/13":
			var e string
			if f.container != "" {
				e = `"instanceEntry":"` + f.container + `","closeTime":"2026-09-30T03:00:00Z",`
			}
			w.Write([]byte(`{"id":13,"title":"c","content":"","category":"Pwn","score":500,"type":"DynamicContainer",
				"context":{` + e + `"url":null}}`))
		case "POST /api/Game/7/Challenges/11":
			if f.submitErr != "" {
				code, b, _ := strings.Cut(f.submitErr, " ")
				w.WriteHeader(map[string]int{"400": 400, "404": 404, "429": 429}[code])
				w.Write([]byte(b))
				return
			}
			var m map[string]string
			json.Unmarshal(body, &m)
			f.gotFlag = f.decode(m["flag"])
			w.Write([]byte(`42`))
		case "GET /api/Game/7/Challenges/11/Status/42":
			if atomic.AddInt32(&f.polls, 1) <= f.pending {
				w.Write([]byte(`"FlagSubmitted"`))
				return
			}
			w.Write([]byte(f.verdict))
		case "GET /api/Account/Profile":
			w.Write([]byte(`{"userId":"u-1","userName":"alice","email":"a@x","role":"User"}`))
		case "POST /api/Game/7/Container/13":
			if f.container != "" {
				w.WriteHeader(400)
				w.Write([]byte(`{"title":"Container already created","status":400}`))
				return
			}
			f.container = "10.0.0.5:31337"
			w.Write([]byte(`{"status":"Running","startedAt":"2026-09-30T01:00:00Z","expectStopAt":"2026-09-30T03:00:00Z","entry":"10.0.0.5:31337"}`))
		case "POST /api/Game/7/Container/13/Extend":
			w.Write([]byte(`{"status":"Running","expectStopAt":"2026-09-30T05:00:00Z","entry":"` + f.container + `"}`))
		case "DELETE /api/Game/7/Container/13":
			f.container = ""
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"title":"Not found","status":404}`))
		}
	})
}

func setup(t *testing.T, f *fake, vals map[string]string) (*Driver, string) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	if _, ok := vals["GZCTF_URL"]; !ok {
		vals["GZCTF_URL"] = srv.URL + "/games/7/challenges"
	} else {
		vals["GZCTF_URL"] = strings.ReplaceAll(vals["GZCTF_URL"], "SRV", srv.URL)
	}
	d, err := New(&driver.Env{Config: &config.Config{Platform: "gzctf", Values: vals}, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	gd := d.(*Driver)
	gd.pollDelay, gd.pollTimeout = time.Millisecond, 2*time.Second
	return gd, srv.URL
}

func TestConfig(t *testing.T) {
	mk := func(v map[string]string) (*Driver, error) {
		d, err := New(&driver.Env{Config: &config.Config{Platform: "gzctf", Values: v}})
		if err != nil {
			return nil, err
		}
		return d.(*Driver), nil
	}
	d, err := mk(map[string]string{"GZCTF_URL": "https://x.example/sub/games/12/challenges/"})
	if err != nil || d.base != "https://x.example/sub" || d.game != "12" {
		t.Fatalf("got %+v %v", d, err)
	}
	d, err = mk(map[string]string{"GZCTF_URL": "https://x.example/games/12", "GZCTF_GAME": "3", "GZCTF_TOKEN": "GZCTF_Token=abc"})
	if err != nil || d.game != "3" || d.cookie != "GZCTF_Token=abc" {
		t.Fatalf("got %+v %v", d, err)
	}
	for _, v := range []map[string]string{
		{"GZCTF_URL": "https://x.example"},
		{"GZCTF_URL": "https://x.example", "GZCTF_GAME": "abc"},
		{"GZCTF_URL": "https://x.example/games/1", "GZCTF_TOKEN": "t", "GZCTF_USERNAME": "u", "GZCTF_PASSWORD": "p"},
		{"GZCTF_URL": "https://x.example/games/1", "GZCTF_USERNAME": "u"},
		{},
	} {
		if _, err := mk(v); ctf.KindOf(err) != ctf.KindConfig {
			t.Errorf("%v: want config error, got %v", v, err)
		}
	}
}

func TestLoginOnceChunkedCookieAndEncryption(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f := &fake{priv: priv, verdict: `"Accepted"`}
	d, _ := setup(t, f, map[string]string{"GZCTF_USERNAME": "alice", "GZCTF_PASSWORD": "pw"})
	ctx := context.Background()
	list, err := d.ListChallenges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Submit(ctx, "11", "flag{x}")
	if err != nil || res.Status != ctf.StatusCorrect || !res.Correct {
		t.Fatalf("submit: %+v %v", res, err)
	}
	if f.logins != 1 || f.gotPass != "pw" || f.gotFlag != "flag{x}" {
		t.Fatalf("logins=%d pass=%q flag=%q", f.logins, f.gotPass, f.gotFlag)
	}
	if len(list) != 3 || list[0].ID != "13" || list[1].ID != "11" || !list[1].Solved || list[2].Solved || *list[1].Solves != 4 {
		t.Fatalf("list: %+v", list)
	}
}

func TestBadLogin(t *testing.T) {
	d, _ := setup(t, &fake{}, map[string]string{"GZCTF_USERNAME": "alice", "GZCTF_PASSWORD": "nope"})
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	d, _ := setup(t, &fake{}, map[string]string{"GZCTF_TOKEN": "stale"})
	_, err := d.ListChallenges(context.Background())
	if ctf.KindOf(err) != ctf.KindAuth || !strings.Contains(err.Error(), "GZCTF_TOKEN") {
		t.Fatalf("got %v", err)
	}
}

func TestSubmitPollsWhileFlagSubmitted(t *testing.T) {
	for verdict, want := range map[string]string{`"Accepted"`: "correct", `"WrongAnswer"`: "incorrect",
		`"CheatDetected"`: "incorrect", `"NotFound"`: "bad_challenge", `1`: "correct", `"Weird"`: "error"} {
		f := &fake{pending: 2, verdict: verdict}
		d, _ := setup(t, f, map[string]string{"GZCTF_TOKEN": "tok"})
		res, err := d.Submit(context.Background(), "11", "flag")
		if err != nil || res.Status != want || res.Correct != (want == "correct") {
			t.Errorf("%s: got %+v %v", verdict, res, err)
		}
		if want != "error" && f.polls != 3 {
			t.Errorf("%s: polls = %d, want 3", verdict, f.polls)
		}
		if f.gotFlag != "flag" {
			t.Errorf("flag sent encrypted without a public key: %q", f.gotFlag)
		}
	}
}

func TestSubmitStillJudging(t *testing.T) {
	f := &fake{pending: 1 << 30}
	d, _ := setup(t, f, map[string]string{"GZCTF_TOKEN": "tok"})
	d.pollTimeout = 20 * time.Millisecond
	_, err := d.Submit(context.Background(), "11", "flag")
	if ctf.KindOf(err) != ctf.KindRemote || !strings.Contains(err.Error(), "still judging submission 42") {
		t.Fatalf("got %v", err)
	}
}

func TestSubmitErrors(t *testing.T) {
	for body, want := range map[string]string{
		`400 {"title":"not started","status":10001}`:  "not_started",
		`400 {"title":"ended","status":10002}`:        "ended",
		`400 {"title":"limit exceeded","status":400}`: "error",
		`429 {"title":"slow down","status":429}`:      "rate_limited",
		`404 {"title":"no chal","status":404}`:        "bad_challenge",
	} {
		d, _ := setup(t, &fake{submitErr: body}, map[string]string{"GZCTF_TOKEN": "tok"})
		res, err := d.Submit(context.Background(), "11", "flag")
		if err != nil || res.Status != want || res.Message == "" {
			t.Errorf("%s: got %+v %v", body, res, err)
		}
	}
	d, _ := setup(t, &fake{}, map[string]string{"GZCTF_TOKEN": "tok"})
	if _, err := d.Submit(context.Background(), "web-a", "flag"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("non-numeric id: %v", err)
	}
}

func TestChallengeSolvesTeamDownload(t *testing.T) {
	d, base := setup(t, &fake{}, map[string]string{"GZCTF_TOKEN": "tok"})
	ctx := context.Background()
	ch, err := d.GetChallenge(ctx, "11")
	if err != nil || ch.Description != "desc" || !ch.Solved || *ch.Solves != 4 || len(ch.Hints) != 2 ||
		*ch.Hints[1].Content != "h2" || ch.Instance != nil || len(ch.Files) != 1 ||
		ch.Files[0].Name != "a.zip" || ch.Files[0].URL != base+"/assets/abc/a.zip" {
		t.Fatalf("got %+v %v", ch, err)
	}
	if _, err := d.GetChallenge(ctx, "99"); ctf.KindOf(err) != ctf.KindNotFound {
		t.Fatalf("missing challenge: %v", err)
	}
	solves, err := d.Solves(ctx)
	if err != nil || len(solves) != 1 || solves[0].Name != "a" || solves[0].Category != "Web" || solves[0].Date == "" {
		t.Fatalf("solves: %+v %v", solves, err)
	}
	ts, err := d.Team(ctx)
	if err != nil || ts.User.Name != "alice" || ts.Team.Name != "team5" || *ts.Team.Place != 3 || *ts.Team.Score != 100 {
		t.Fatalf("team: %+v %v", ts, err)
	}
	dr, _ := d.PrepareDownload(ctx, ch.Files[0].URL)
	if dr.Headers["Cookie"] != "GZCTF_Token=tok" {
		t.Fatalf("same-origin download missing cookie: %+v", dr)
	}
	dr, _ = d.PrepareDownload(ctx, "https://cdn.example/a.zip")
	if len(dr.Headers) != 0 {
		t.Fatal("cookie leaked cross-origin")
	}
}

func TestPublicScoreboard(t *testing.T) {
	d, _ := setup(t, &fake{}, map[string]string{})
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Limit: 1, Offset: 1})
	if err != nil || sb.Total != 3 || len(sb.Entries) != 1 || sb.Entries[0].Name != "B" || sb.Entries[0].Position != 2 {
		t.Fatalf("got %+v %v", sb, err)
	}
	sb, err = d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Division: "students"})
	if err != nil || sb.Total != 2 || sb.Entries[1].Name != "C" || sb.Entries[1].Position != 2 {
		t.Fatalf("division: %+v %v", sb, err)
	}
	if _, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Division: "nope"}); ctf.KindOf(err) != ctf.KindNotFound {
		t.Fatalf("unknown division: %v", err)
	}
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("no-auth listing should be config error: %v", err)
	}
}

func TestInstanceLifecycle(t *testing.T) {
	f := &fake{}
	d, _ := setup(t, f, map[string]string{"GZCTF_TOKEN": "tok"})
	ctx := context.Background()
	step := func(action, wantStatus string) *ctf.Instance {
		t.Helper()
		inst, err := d.Instance(ctx, action, "13")
		if err != nil || inst.Status != wantStatus {
			t.Fatalf("%s: got %+v %v", action, inst, err)
		}
		return inst
	}
	step(ctf.InstanceStatus, "not_started")
	inst := step(ctf.InstanceStart, "started")
	if inst.Host != "10.0.0.5:31337" || inst.Connect.Command != "nc 10.0.0.5 31337" || inst.Expires == "" {
		t.Fatalf("start: %+v", inst)
	}
	if inst := step(ctf.InstanceStart, "error"); inst.Message != "Container already created" || inst.HTTPStatus != 400 {
		t.Fatalf("restart: %+v", inst)
	}
	step(ctf.InstanceStatus, "running")
	if inst := step(ctf.InstanceExtend, "extended"); inst.Expires != "2026-09-30T05:00:00Z" {
		t.Fatalf("extend: %+v", inst)
	}
	step(ctf.InstanceStop, "terminated")
	step(ctf.InstanceStatus, "not_started")
	if _, err := d.Instance(ctx, ctf.InstanceStatus, "11"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Fatalf("non-container: %v", err)
	}
	ch, _ := d.GetChallenge(ctx, "13")
	if ch.Instance == nil || ch.Instance.Slug != "13" {
		t.Fatalf("container challenge ref: %+v", ch)
	}
}

func TestProxyEntry(t *testing.T) {
	d := &Driver{base: "https://x.example/sub"}
	c := d.connect("6f1b2c3d-0000-4000-8000-000000000000")
	if c.URL != "wss://x.example/sub/api/Proxy/6f1b2c3d-0000-4000-8000-000000000000" || c.Host != "" {
		t.Fatalf("got %+v", c)
	}
}

func TestDetect(t *testing.T) {
	d, base := setup(t, &fake{}, map[string]string{"GZCTF_TOKEN": "tok"})
	_ = d
	det, ok := Detect(context.Background(), http.DefaultClient, base+"/games/7/challenges")
	if !ok || det.BaseURL != base || det.Values["GZCTF_GAME"] != "7" {
		t.Fatalf("got %+v %v", det, ok)
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><title>GZ::CTF</title></html>`))
			return
		}
		w.WriteHeader(404)
	}))
	defer html.Close()
	if det, ok := Detect(context.Background(), http.DefaultClient, html.URL); !ok || det.Values != nil {
		t.Fatalf("html fallback: %+v %v", det, ok)
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":{}}`))
	}))
	defer other.Close()
	if _, ok := Detect(context.Background(), http.DefaultClient, other.URL); ok {
		t.Fatal("false positive")
	}
}
