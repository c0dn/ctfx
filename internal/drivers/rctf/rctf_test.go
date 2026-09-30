package rctf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

func setup(t *testing.T, vals map[string]string, submitKind string) (*Driver, *int32) {
	t.Helper()
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/auth/login":
			atomic.AddInt32(&logins, 1)
			var b map[string]string
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &b)
			if b["teamToken"] != "team" {
				w.WriteHeader(401)
				w.Write([]byte(`{"kind":"badTokenVerification","message":"bad team token"}`))
				return
			}
			w.Write([]byte(`{"kind":"goodLogin","data":{"authToken":"auth"}}`))
			return
		case "GET /api/v1/leaderboard/now":
			if r.URL.Query().Get("offset") != "1" {
				t.Errorf("offset not forwarded: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"kind":"goodLeaderboard","data":{"total":9,"leaderboard":[{"id":"t2","name":"B","score":50}]}}`))
			return
		}
		if auth != "Bearer auth" {
			w.WriteHeader(401)
			w.Write([]byte(`{"kind":"badToken","message":"bad token"}`))
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/challs":
			w.Write([]byte(`{"kind":"goodChallenges","data":[
				{"id":"c2","name":"two","category":"web","points":200,"solves":1,"author":"x","files":[{"name":"a.zip","url":"https://cdn.example/a.zip"}]},
				{"id":"c1","name":"one","category":"web","points":{"min":50,"max":100},"solves":"3"}]}`))
		case "GET /api/v1/users/me":
			w.Write([]byte(`{"kind":"goodUserData","data":{"id":"u","name":"team","score":100,"globalPlace":4,
				"solves":[{"id":"c2","name":"two","category":"web","points":200,"createdAt":1700000000000}]}}`))
		case "GET /api/v1/users/me/members":
			w.WriteHeader(403)
			w.Write([]byte(`{"kind":"badPerms","message":"members disabled"}`))
		case "POST /api/v1/challs/c1/submit":
			w.Write([]byte(`{"kind":"` + submitKind + `","message":"m"}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"kind":"badEndpoint","message":"no"}`))
		}
	}))
	t.Cleanup(srv.Close)
	vals["RCTF_URL"] = srv.URL
	d, err := New(&driver.Env{Config: &config.Config{Platform: "rctf", Values: vals}, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Driver), &logins
}

func TestTeamTokenExchangedOnce(t *testing.T) {
	d, logins := setup(t, map[string]string{"RCTF_TEAM_TOKEN": "team"}, "goodFlag")
	ctx := context.Background()
	list, err := d.ListChallenges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Solves(ctx); err != nil {
		t.Fatal(err)
	}
	if *logins != 1 {
		t.Fatalf("logins = %d", *logins)
	}
	if list[0].ID != "c1" || *list[0].Points != 100 || *list[0].Solves != 3 || list[1].Solved != true {
		t.Fatalf("list: %+v", list)
	}
}

func TestBadTeamToken(t *testing.T) {
	d, _ := setup(t, map[string]string{"RCTF_TEAM_TOKEN": "wrong"}, "goodFlag")
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("got %v", err)
	}
}

func TestSubmitKinds(t *testing.T) {
	for kind, want := range map[string]string{"goodFlag": "correct", "badFlag": "incorrect",
		"badAlreadySolvedChallenge": "already_solved", "badRateLimit": "rate_limited", "badWeird": "error"} {
		d, _ := setup(t, map[string]string{"RCTF_AUTH_TOKEN": "auth"}, kind)
		res, err := d.Submit(context.Background(), "c1", "flag")
		if err != nil || res.Status != want || res.Correct != (want == "correct") {
			t.Errorf("%s: got %+v %v", kind, res, err)
		}
	}
}

func TestPublicScoreboardAndTeam(t *testing.T) {
	d, _ := setup(t, map[string]string{}, "goodFlag")
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Limit: 5, Offset: 1})
	if err != nil || sb.Total != 9 || sb.Entries[0].Position != 2 {
		t.Fatalf("got %+v %v", sb, err)
	}
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("no-auth listing should be config error: %v", err)
	}
	d, _ = setup(t, map[string]string{"RCTF_AUTH_TOKEN": "auth"}, "goodFlag")
	ts, err := d.Team(context.Background())
	if err != nil || ts.Team.Name != "team" || ts.TeamError != "members disabled" || *ts.User.Place != 4 {
		t.Fatalf("got %+v %v", ts, err)
	}
	ch, err := d.GetChallenge(context.Background(), "c2")
	if err != nil || ch.Files[0].Name != "a.zip" {
		t.Fatalf("got %+v %v", ch, err)
	}
	dr, _ := d.PrepareDownload(context.Background(), ch.Files[0].URL)
	if len(dr.Headers) != 0 {
		t.Fatal("bearer leaked cross-origin")
	}
}

func TestV2ChallsFallbackAndStringSolves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/challs":
			w.Write([]byte(`{"kind":"goodChallenges","data":[{"id":"a","name":"A","category":"web","points":10},{"id":"b","name":"B","category":"web","points":20}]}`))
		case "/api/v1/users/me":
			w.Write([]byte(`{"kind":"goodUserData","data":{"solves":["a",{"challengeId":"b"}]}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"kind":"badEndpoint","message":"no"}`))
		}
	}))
	t.Cleanup(srv.Close)
	d, _ := New(&driver.Env{Config: &config.Config{Platform: "rctf", Values: map[string]string{"RCTF_URL": srv.URL, "RCTF_AUTH_TOKEN": "x"}}, Client: srv.Client()})
	list, err := d.ListChallenges(context.Background())
	if err != nil || len(list) != 2 || !list[0].Solved || !list[1].Solved {
		t.Fatalf("got %+v %v", list, err)
	}
}

func TestAmbiguousConfig(t *testing.T) {
	_, err := New(&driver.Env{Config: &config.Config{Platform: "rctf", Values: map[string]string{
		"RCTF_URL": "https://x", "RCTF_AUTH_TOKEN": "a", "RCTF_TEAM_TOKEN": "b"}}})
	if ctf.KindOf(err) != ctf.KindConfig {
		t.Fatalf("got %v", err)
	}
}
