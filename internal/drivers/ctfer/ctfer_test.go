package ctfer

import (
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// fakeCTFer is a minimal stand-in for the real platform: it issues a session
// cookie carrying a rotating CSRF token, checks the CSRF on the login form and
// on submit, and flashes the submit verdict back into the cookie exactly as
// Flask does.
type fakeCTFer struct {
	loggedIn bool
	solved   map[int]bool
	nextCSRF string
}

func encodeSession(st map[string]any) string {
	raw, _ := json.Marshal(st)
	// Match the production app: zlib-compressed, dot-prefixed, no real signature.
	var b strings.Builder
	zw := zlib.NewWriter(&b)
	zw.Write(raw)
	zw.Close()
	return "." + base64.RawURLEncoding.EncodeToString([]byte(b.String())) + ".ts.sig"
}

func (f *fakeCTFer) setSession(w http.ResponseWriter, flashes [][2]string) {
	st := map[string]any{"csrf": f.nextCSRF, "user_id": 23}
	if len(flashes) > 0 {
		var fl []any
		for _, fv := range flashes {
			fl = append(fl, map[string]any{" t": []string{fv[0], fv[1]}})
		}
		st["_flashes"] = fl
	}
	http.SetCookie(w, &http.Cookie{Name: "ctfer_test_session", Value: encodeSession(st), Path: "/"})
}

func (f *fakeCTFer) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			f.nextCSRF = "csrf-get"
			f.setSession(w, nil)
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<meta name="csrf-token" content="csrf-get"><script src="/static/react/app.js">`)
			return
		}
		r.ParseForm()
		if r.FormValue("csrf") != "csrf-get" {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid CSRF token")
			return
		}
		if r.FormValue("username") == "c0dn" && r.FormValue("password") == "pw" {
			f.loggedIn = true
			f.nextCSRF = "csrf-authed"
			f.setSession(w, nil)
			w.Header().Set("Location", "/timeline")
			w.WriteHeader(302)
			return
		}
		f.nextCSRF = "csrf-get"
		f.setSession(w, [][2]string{{"error", "Invalid credentials"}})
		w.Header().Set("Location", "/login")
		w.WriteHeader(302)
	})
	mux.HandleFunc("/api/ui/context", func(w http.ResponseWriter, r *http.Request) {
		if !f.loggedIn {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"authentication required"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"csrf": f.nextCSRF,
			"user": map[string]any{"id": 23, "username": "c0dn", "team": "n0l3rain", "is_admin": false},
		})
	})
	mux.HandleFunc("/api/ui/investigation", func(w http.ResponseWriter, r *http.Request) {
		if !f.loggedIn {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"challenges": []map[string]any{
			{"id": 35, "name": "The Support Session", "category": "Investigation", "value": 150, "solve_count": 9, "order": 0, "solved": f.solved[35]},
			{"id": 37, "name": "Unknown Service Binary", "category": "Investigation", "value": 475, "solve_count": 5, "order": 2, "solved": f.solved[37]},
		}})
	})
	mux.HandleFunc("/api/ui/team", func(w http.ResponseWriter, r *http.Request) {
		if !f.loggedIn {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"team": map[string]any{
			"id": 12, "name": "n0l3rain", "members": []string{"c0dn", "j041"}, "invite_code": "abc",
		}})
	})
	mux.HandleFunc("/api/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"standings": []map[string]any{
			{"name": "n0l3rain", "score": 150, "playtester": false},
			{"name": "IKOM", "score": 0, "playtester": false},
		}})
	})
	mux.HandleFunc("/api/ui/challenge/", func(w http.ResponseWriter, r *http.Request) {
		if !f.loggedIn {
			w.WriteHeader(401)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/ui/challenge/")
		n := 0
		fmt.Sscanf(id, "%d", &n)
		json.NewEncoder(w).Encode(map[string]any{
			"id": n, "name": "The Support Session", "category": "Investigation",
			"description": "Submit CHN{...}", "value": 150, "solved": f.solved[n],
			"max_attempts": 20, "remaining_attempts": 20, "submission_example": "CHN{ANSWER}",
			"hints": []map[string]any{{"id": n, "cost": 50, "unlocked": false, "content": nil}},
		})
	})
	mux.HandleFunc("/challenge/", func(w http.ResponseWriter, r *http.Request) {
		// /challenge/<id>/submit
		if !strings.HasSuffix(r.URL.Path, "/submit") {
			w.WriteHeader(404)
			return
		}
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/challenge/"), "%d", &n)
		r.ParseForm()
		if r.FormValue("csrf") != f.nextCSRF {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid CSRF token")
			return
		}
		f.nextCSRF = "csrf-after-submit"
		flag := r.FormValue("flag")
		var flash [2]string
		switch {
		case flag == "CHN{right}":
			f.solved[n] = true
			flash = [2]string{"success", "Correct! Finding solved."}
		case flag == "CHN{closed}":
			flash = [2]string{"error", "Submissions are not open for this scenario."}
		default:
			flash = [2]string{"error", "Incorrect submission."}
		}
		f.setSession(w, [][2]string{flash})
		w.Header().Set("Location", fmt.Sprintf("/challenge/%d", n))
		w.WriteHeader(302)
	})
	return mux
}

func newFake(t *testing.T, vals map[string]string) (*Driver, *fakeCTFer) {
	t.Helper()
	f := &fakeCTFer{solved: map[int]bool{}}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	vals["CTFER_URL"] = srv.URL
	d, err := New(&driver.Env{Config: &config.Config{Platform: "ctfer", Values: vals}, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Driver), f
}

func TestNewValidation(t *testing.T) {
	bad := []map[string]string{
		{"CTFER_URL": "https://x"},                           // no auth
		{"CTFER_URL": "https://x", "CTFER_USERNAME": "c0dn"}, // password missing
		{"CTFER_URL": "https://x", "CTFER_PASSWORD": "pw"},   // username missing
	}
	for i, vals := range bad {
		if _, err := New(&driver.Env{Config: &config.Config{Platform: "ctfer", Values: vals}, Client: http.DefaultClient}); err == nil {
			t.Errorf("case %d: expected config error, got nil", i)
		}
	}
}

func TestLoginAndListChallenges(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "pw"})
	chals, err := d.ListChallenges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(chals) != 2 || chals[0].ID != "35" || chals[0].Name != "The Support Session" {
		t.Fatalf("unexpected challenges: %+v", chals)
	}
	if chals[0].Extra["slug"] == nil {
		t.Error("expected extra metadata on challenge")
	}
}

func TestLoginBadPassword(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "wrong"})
	_, err := d.ListChallenges(context.Background())
	if err == nil || ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("expected auth error, got %v (kind %q)", err, ctf.KindOf(err))
	}
}

func TestSubmitCorrect(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "pw"})
	res, err := d.Submit(context.Background(), "35", "CHN{right}")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Correct || res.Status != ctf.StatusCorrect {
		t.Fatalf("expected correct, got %+v", res)
	}
}

func TestSubmitIncorrect(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "pw"})
	res, err := d.Submit(context.Background(), "35", "CHN{nope}")
	if err != nil {
		t.Fatal(err)
	}
	if res.Correct || res.Status != ctf.StatusIncorrect {
		t.Fatalf("expected incorrect, got %+v", res)
	}
}

func TestSubmitNotOpen(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "pw"})
	res, err := d.Submit(context.Background(), "35", "CHN{closed}")
	if err != nil {
		t.Fatal(err)
	}
	if res.Correct || res.Status != ctf.StatusNotStarted {
		t.Fatalf("expected not_started, got %+v", res)
	}
}

func TestTeamAndScoreboard(t *testing.T) {
	d, _ := newFake(t, map[string]string{"CTFER_USERNAME": "c0dn", "CTFER_PASSWORD": "pw"})
	ts, err := d.Team(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ts.User.Name != "c0dn" || ts.Team == nil || ts.Team.Name != "n0l3rain" || len(ts.Team.Members) != 2 {
		t.Fatalf("unexpected team status: %+v / %+v", ts.User, ts.Team)
	}
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Total != 2 || sb.Entries[0].Name != "n0l3rain" || sb.Entries[0].Score != 150 {
		t.Fatalf("unexpected scoreboard: %+v", sb)
	}
}

func TestSessionCookieAuth(t *testing.T) {
	// Seed a valid-looking session cookie and log in without username/password.
	cookie := encodeSession(map[string]any{"csrf": "x", "user_id": 23})
	d, f := newFake(t, map[string]string{"CTFER_SESSION_COOKIE": cookie, "CTFER_SESSION_COOKIE_NAME": "ctfer_test_session"})
	f.loggedIn = true // the pasted cookie represents an already-authenticated browser session
	if _, err := d.ListChallenges(context.Background()); err != nil {
		t.Fatalf("session-cookie auth failed: %v", err)
	}
}

func TestDecodeFlaskSessionRoundTrip(t *testing.T) {
	enc := encodeSession(map[string]any{"csrf": "tok123", "user_id": 23,
		"_flashes": []any{map[string]any{" t": []string{"error", "Invalid credentials"}}}})
	st, ok := decodeFlaskSession(enc)
	if !ok || st.CSRF != "tok123" || st.UserID != 23 || len(st.Flashes) != 1 || st.Flashes[0][1] != "Invalid credentials" {
		t.Fatalf("decode failed: ok=%v st=%+v", ok, st)
	}
}

func TestClassifyFlash(t *testing.T) {
	cases := []struct {
		cat, msg string
		status   int
		want     string
	}{
		{"success", "Correct! Finding solved.", 302, ctf.StatusCorrect},
		{"error", "Incorrect submission.", 302, ctf.StatusIncorrect},
		{"error", "Submissions are not open for this scenario.", 302, ctf.StatusNotStarted},
		{"error", "This scenario has ended.", 302, ctf.StatusEnded},
		{"error", "You have already solved this.", 302, ctf.StatusAlreadySolved},
		{"success", "This finding is already confirmed; no attempt was consumed.", 302, ctf.StatusAlreadySolved},
		{"error", "Too many attempts, wait.", 302, ctf.StatusRateLimited},
		{"", "", 302, ctf.StatusError},
	}
	for _, c := range cases {
		if got := classifyFlash(c.cat, c.msg, c.status); got != c.want {
			t.Errorf("classifyFlash(%q,%q)=%q want %q", c.cat, c.msg, got, c.want)
		}
	}
}

func TestURLHelper(t *testing.T) {
	u, _ := url.Parse("https://ctf.example.local")
	d := &Driver{base: "https://ctf.example.local", baseURL: u}
	if got := d.url("/api/ui/investigation"); got != "https://ctf.example.local/api/ui/investigation" {
		t.Errorf("url join: %q", got)
	}
}
