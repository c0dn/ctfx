package htb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// submitCapture records the last POST /api/flags/own request for assertions.
type submitCapture struct {
	ChallengeID int
	Flag        string
	Auth        string
}

const eventJSON = `{"challenges":[
	{"id":10,"name":"Beta","points":200,"challenge_category_id":2,"description":"d2","content":"full body 2","creator":"bob","filename":"b.zip","solved":true,"solves":5},
	{"id":11,"name":"Alpha","points":100,"challenge_category_id":1,"description":"d1","creator":"amy","filename":"","solved":false,"solves":3}
]}`

const categoriesJSON = `[{"id":1,"name":"web"},{"id":2,"name":"pwn"}]`

const scoresJSON = `{"scores":[
	{"id":1,"name":"T1","points":500,"owned_flags":5,"country_code":"US"},
	{"id":2,"name":"T2","points":400,"owned_flags":4,"country_code":"DE"},
	{"id":3,"name":"T3","points":300,"owned_flags":3,"country_code":"FR"}
]}`

func newServer(t *testing.T) (*httptest.Server, *submitCapture) {
	t.Helper()
	cap := &submitCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer jwt" {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/ctf/5":
			w.Write([]byte(eventJSON))
		case "GET /api/public/challenge-categories":
			w.Write([]byte(categoriesJSON))
		case "GET /api/ctfs/scores/5":
			w.Write([]byte(scoresJSON))
		case "POST /api/flags/own":
			raw, _ := io.ReadAll(r.Body)
			var b struct {
				ChallengeID int    `json:"challenge_id"`
				Flag        string `json:"flag"`
			}
			json.Unmarshal(raw, &b)
			cap.ChallengeID, cap.Flag, cap.Auth = b.ChallengeID, b.Flag, r.Header.Get("Authorization")
			switch b.Flag {
			case "right":
				w.WriteHeader(200)
				w.Write([]byte(`{"message":"Congratulations"}`))
			case "wrong":
				w.WriteHeader(400)
				w.Write([]byte(`{"message":"Incorrect flag"}`))
			case "slow":
				w.WriteHeader(429)
				w.Write([]byte(`{"message":"Too many requests"}`))
			case "dup":
				w.WriteHeader(400)
				w.Write([]byte(`{"message":"You have already solved this challenge"}`))
			default:
				w.WriteHeader(400)
				w.Write([]byte(`{"message":"Incorrect flag"}`))
			}
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"message":"nope"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func build(t *testing.T, srv *httptest.Server, vals map[string]string) *Driver {
	t.Helper()
	full := map[string]string{"HTB_URL": srv.URL}
	for k, v := range vals {
		full[k] = v
	}
	d, err := New(&driver.Env{Config: &config.Config{Platform: "htb", Values: full}, Client: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d.(*Driver)
}

func TestConfigErrors(t *testing.T) {
	// Neither URL nor token is a config error at construction.
	if _, err := New(&driver.Env{Config: &config.Config{Platform: "htb", Values: map[string]string{}}}); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("empty config: got %v", err)
	}
	srv, _ := newServer(t)
	// Missing token: fails lazily on use with a config error.
	d := build(t, srv, map[string]string{"HTB_EVENT": "5"})
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("no token: got %v", err)
	}
	// Missing event: fails lazily on use with a config error.
	d = build(t, srv, map[string]string{"HTB_TOKEN": "jwt"})
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("no event: got %v", err)
	}
}

func TestListChallenges(t *testing.T) {
	srv, _ := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	list, err := d.ListChallenges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d", len(list))
	}
	// Sorted by category: "pwn" < "web".
	beta, alpha := list[0], list[1]
	if beta.Name != "Beta" || beta.Category != "pwn" || !beta.Solved || *beta.Points != 200 || *beta.Solves != 5 {
		t.Fatalf("beta: %+v", beta)
	}
	if alpha.Name != "Alpha" || alpha.Category != "web" || alpha.Solved || *alpha.Points != 100 {
		t.Fatalf("alpha: %+v", alpha)
	}
	if beta.Description != "" || beta.Files != nil {
		t.Fatalf("listing should be lean: %+v", beta)
	}
}

func TestGetChallenge(t *testing.T) {
	srv, _ := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	ch, err := d.GetChallenge(context.Background(), "10")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Description != "full body 2" || len(ch.Files) != 1 || ch.Files[0].Name != "b.zip" {
		t.Fatalf("challenge 10: %+v", ch)
	}
	if ch.Files[0].URL != srv.URL+"/api/challenges/10/download" {
		t.Fatalf("download URL: %s", ch.Files[0].URL)
	}
	if _, err := d.GetChallenge(context.Background(), "999"); ctf.KindOf(err) != ctf.KindNotFound {
		t.Fatalf("missing: got %v", err)
	}
}

func TestSubmit(t *testing.T) {
	srv, cap := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	ctx := context.Background()

	res, err := d.Submit(ctx, "1", "right")
	if err != nil || res.Status != ctf.StatusCorrect || !res.Correct {
		t.Fatalf("correct: %+v %v", res, err)
	}
	if cap.ChallengeID != 1 || cap.Flag != "right" || cap.Auth != "Bearer jwt" {
		t.Fatalf("submit request not shaped correctly: %+v", cap)
	}

	res, err = d.Submit(ctx, "1", "wrong")
	if err != nil || res.Status != ctf.StatusIncorrect || res.Correct || res.Message == "" {
		t.Fatalf("incorrect: %+v %v", res, err)
	}

	res, err = d.Submit(ctx, "1", "slow")
	if err != nil || res.Status != ctf.StatusRateLimited {
		t.Fatalf("rate limited: %+v %v", res, err)
	}

	res, err = d.Submit(ctx, "1", "dup")
	if err != nil || res.Status != ctf.StatusAlreadySolved {
		t.Fatalf("already solved: %+v %v", res, err)
	}

	if _, err := d.Submit(ctx, "abc", "x"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("bad id: got %v", err)
	}
}

func TestScoreboardSlicing(t *testing.T) {
	srv, _ := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Total != 3 {
		t.Fatalf("total = %d", sb.Total)
	}
	if len(sb.Entries) != 1 || sb.Entries[0].Position != 2 || sb.Entries[0].Name != "T2" || sb.Entries[0].Score != 400 {
		t.Fatalf("entries: %+v", sb.Entries)
	}
}

func TestSolves(t *testing.T) {
	srv, _ := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	solves, err := d.Solves(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(solves) != 1 || solves[0].ChallengeID != "10" || solves[0].Category != "pwn" {
		t.Fatalf("solves: %+v", solves)
	}
}

func TestPrepareDownload(t *testing.T) {
	srv, _ := newServer(t)
	d := build(t, srv, map[string]string{"HTB_EVENT": "5", "HTB_TOKEN": "jwt"})
	ctx := context.Background()

	same := srv.URL + "/api/challenges/10/download"
	dr, err := d.PrepareDownload(ctx, same)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Headers["Authorization"] != "Bearer jwt" {
		t.Fatalf("same-origin should carry the bearer: %+v", dr.Headers)
	}

	dr, err = d.PrepareDownload(ctx, "https://cdn.example/x.zip")
	if err != nil {
		t.Fatal(err)
	}
	if len(dr.Headers) != 0 {
		t.Fatalf("bearer leaked cross-origin: %+v", dr.Headers)
	}
}

func TestDetect(t *testing.T) {
	det, ok := Detect(context.Background(), http.DefaultClient, "https://ctf.hackthebox.com/event/42/challenges")
	if !ok || det.BaseURL != defaultBase || det.Values["HTB_EVENT"] != "42" {
		t.Fatalf("event URL: %+v %v", det, ok)
	}
	det, ok = Detect(context.Background(), http.DefaultClient, "ctf.hackthebox.com")
	if !ok || det.BaseURL != defaultBase || len(det.Values) != 0 {
		t.Fatalf("bare host: %+v %v", det, ok)
	}
	if _, ok := Detect(context.Background(), http.DefaultClient, "https://ctfd.example.com"); ok {
		t.Fatal("non-HTB host should not match")
	}
}
