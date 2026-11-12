package ctfd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

type seen struct {
	method, path, query, auth, cookie, ctype, csrf string
	body                                           map[string]any
}

func server(t *testing.T, log *[]seen, routes map[string]func(w http.ResponseWriter, s seen)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seen{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization"), cookie: r.Header.Get("Cookie"),
			ctype: r.Header.Get("Content-Type"), csrf: r.Header.Get("CSRF-Token")}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &s.body)
		*log = append(*log, s)
		h, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"message":"nope"}`))
			return
		}
		h(w, s)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newDriver(t *testing.T, srv *httptest.Server, vals map[string]string) *Driver {
	t.Helper()
	vals["CTFD_URL"] = srv.URL + "/"
	d, err := New(&driver.Env{Config: &config.Config{Platform: "ctfd", Values: vals}, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Driver)
}

func reply(body string) func(http.ResponseWriter, seen) {
	return func(w http.ResponseWriter, _ seen) { w.Write([]byte(body)) }
}

func TestTokenAuthSendsJSONContentType(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/challenges": reply(`{"success":true,"data":[
			{"id":2,"name":"b","category":"web","value":200,"solved_by_me":true,"solves":4},
			{"id":1,"name":"a","category":"web","value":100,"solves":null,"type":"kubectf","template_name":"a-slug"}]}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	list, err := d.ListChallenges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if log[0].auth != "Token tok" || log[0].ctype != "application/json" {
		t.Fatalf("headers: %+v", log[0])
	}
	if len(list) != 2 || list[0].ID != "1" || list[1].Solved != true || *list[1].Solves != 4 || list[0].Solves != nil {
		t.Fatalf("list: %+v", list)
	}
	if list[0].Instance == nil || list[0].Instance.Slug != "a-slug" {
		t.Fatalf("instance ref missing: %+v", list[0])
	}
}

func TestGetChallengeFilesAndHints(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/challenges/7": reply(`{"success":true,"data":{"id":7,"name":"pwn1","category":"pwn","value":300,
			"description":"desc","connection_info":"nc x 1","files":["/files/abc/pwn1.zip?token=q"],
			"hints":[{"id":3,"cost":10},{"id":4,"cost":0,"content":"look"}]}}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	ch, err := d.GetChallenge(context.Background(), "7")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Files[0].Name != "pwn1.zip" || ch.Files[0].URL != srv.URL+"/files/abc/pwn1.zip?token=q" {
		t.Fatalf("files: %+v", ch.Files)
	}
	if !ch.Hints[0].Locked || ch.Hints[1].Locked || *ch.Hints[1].Content != "look" {
		t.Fatalf("hints: %+v", ch.Hints)
	}
	if _, err := d.GetChallenge(context.Background(), "pwn1"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("non-numeric ID should be usage error: %v", err)
	}
	if _, err := d.GetChallenge(context.Background(), "8"); ctf.KindOf(err) != ctf.KindNotFound {
		t.Fatalf("missing challenge should be not_found: %v", err)
	}
}

// Boards that keep handouts in the description (Hack@UCF's archive) get them
// as files: Markdown and HTML links to this platform's /files/, decoded,
// once each. Other hosts, other paths and already-attached files are left out.
func TestDescriptionLinksBecomeFiles(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/challenges/9": reply(`{"success":true,"data":{"id":9,"name":"ret","category":"pwn","value":100,
			"description":"Get the flag.\n\n* [ret](/files/hackucf/Pwn/ret/ret)\n* [libc](/files/hackucf/Pwn/ret/libc.so.6 \"libc\")\n<a href=\"/files/a%20b/notes.txt?x=1&amp;y=2\">notes</a>\n[again](/files/hackucf/Pwn/ret/ret)\n[att](/files/abc/att.zip)\n[writeup](https://github.com/x/y/blob/main/ret)\n[rules](/rules)\n[dir](/files/hackucf/)",
			"files":["/files/abc/att.zip"]}}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	ch, err := d.GetChallenge(context.Background(), "9")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range ch.Files {
		got = append(got, f.Name+" "+strings.TrimPrefix(f.URL, srv.URL))
	}
	want := []string{"att.zip /files/abc/att.zip", "ret /files/hackucf/Pwn/ret/ret", "libc.so.6 /files/hackucf/Pwn/ret/libc.so.6", "notes.txt /files/a%20b/notes.txt?x=1&y=2"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("files:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A description link downloads with the platform's credentials like an attachment.
	dr, err := d.PrepareDownload(context.Background(), ch.Files[1].URL)
	if err != nil || dr.Headers["Authorization"] != "Token tok" {
		t.Fatalf("download request %+v %v", dr, err)
	}
}

func TestSubmitMapping(t *testing.T) {
	var log []seen
	status := "incorrect"
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"POST /api/v1/challenges/attempt": func(w http.ResponseWriter, _ seen) {
			w.Write([]byte(`{"success":true,"data":{"status":"` + status + `","message":"m"}}`))
		},
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	res, err := d.Submit(context.Background(), "5", "flag{x}")
	if err != nil || res.Status != ctf.StatusIncorrect || res.Correct {
		t.Fatalf("got %+v %v", res, err)
	}
	if log[0].body["challenge_id"] != float64(5) || log[0].body["submission"] != "flag{x}" {
		t.Fatalf("body: %v", log[0].body)
	}
	status = "correct"
	if res, _ := d.Submit(context.Background(), "5", "f"); !res.Correct {
		t.Fatal("expected correct")
	}
	status = "ratelimited"
	if res, _ := d.Submit(context.Background(), "5", "f"); res.Status != ctf.StatusRateLimited {
		t.Fatalf("got %s", res.Status)
	}
}

func TestDictFilesAndTeamSolves(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/challenges/3":    reply(`{"success":true,"data":{"id":3,"name":"c","files":[{"location":"/files/z/c.tar"}]}}`),
		"GET /api/v1/teams/me/solves": reply(`{"success":true,"data":[{"challenge_id":3,"challenge":{"name":"c","category":"web","value":50},"date":"d"}]}`),
		"GET /api/v1/users/me/solves": reply(`{"success":true,"data":[]}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	ch, err := d.GetChallenge(context.Background(), "3")
	if err != nil || len(ch.Files) != 1 || ch.Files[0].Name != "c.tar" {
		t.Fatalf("dict files: %+v %v", ch, err)
	}
	solves, err := d.Solves(context.Background())
	if err != nil || len(solves) != 1 || solves[0].ChallengeID != "3" {
		t.Fatalf("team solves: %+v %v", solves, err)
	}
}

func TestUserModeSolvesFallback(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/teams/me/solves": func(w http.ResponseWriter, _ seen) { w.WriteHeader(403) },
		"GET /api/v1/users/me/solves": reply(`{"success":true,"data":[{"challenge_id":1,"challenge":{"name":"a"}}]}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	solves, err := d.Solves(context.Background())
	if err != nil || len(solves) != 1 || solves[0].Name != "a" {
		t.Fatalf("got %+v %v", solves, err)
	}
}

func TestAuthFailureIsAuthKind(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/users/me/solves": func(w http.ResponseWriter, _ seen) { w.WriteHeader(401) },
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	if _, err := d.Solves(context.Background()); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("got %v", err)
	}
}

func TestKubeCTFSessionAuthAndCSRF(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/challenges/9": reply(`{"success":true,"data":{"id":9,"name":"k","type":"kubectf","template_name":"kslug"}}`),
		"POST /api/kube_ctf/kslug": reply(`{"deployment":{"name":"d","host":"pwn-k.ctf.example","expires":"soon","owner":7}}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok", "CTFD_SESSION_COOKIE": "session=sess", "CTFD_CSRF_TOKEN": "csrf"})
	inst, err := d.Instance(context.Background(), ctf.InstanceStart, "9")
	if err != nil {
		t.Fatal(err)
	}
	last := log[len(log)-1]
	if last.cookie != "session=sess" || last.csrf != "csrf" || last.auth != "" || last.body["action"] != "create" {
		t.Fatalf("plugin request: %+v", last)
	}
	if inst.State != ctf.InstanceRunning || inst.Owner != "7" || inst.Connect == nil || inst.Connect.Command == "" {
		t.Fatalf("instance: %+v", inst)
	}
	st, err := d.Instance(context.Background(), ctf.InstanceStatus, "missing-slug")
	if err != nil || st.State != ctf.InstanceStopped {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestWhaleInstance(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"POST /api/v1/plugins/ctfd-whale/container": reply(`{"success":true,"data":{"ip":"10.0.0.1","port":"30000"}}`),
		"GET /api/v1/plugins/ctfd-whale/container":  func(w http.ResponseWriter, _ seen) { w.WriteHeader(404) },
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok", "CTFD_INSTANCE": "whale"})
	start, err := d.Instance(context.Background(), ctf.InstanceStart, "5")
	if err != nil {
		t.Fatal(err)
	}
	if start.State != ctf.InstanceRunning || start.Backend != "whale" || start.Connect.Host != "10.0.0.1:30000" || start.Connect.Port != 30000 ||
		start.Connect == nil || start.Connect.Command != "nc 10.0.0.1 30000" {
		t.Fatalf("start: %+v (connect %+v)", start, start.Connect)
	}
	last := log[len(log)-1]
	if last.body["challenge_id"] != float64(5) {
		t.Fatalf("whale start body: %v", last.body)
	}
	st, err := d.Instance(context.Background(), ctf.InstanceStatus, "5")
	if err != nil || st.State != ctf.InstanceStopped {
		t.Fatalf("status: %+v %v", st, err)
	}
	if !strings.Contains(log[len(log)-1].query, "challenge_id=5") {
		t.Fatalf("status query missing challenge_id: %q", log[len(log)-1].query)
	}
	if _, err := d.Instance(context.Background(), ctf.InstanceStart, "not-a-number"); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("non-numeric id should be usage error: %v", err)
	}
}

func TestScoreboardAndDownloadHeaders(t *testing.T) {
	var log []seen
	srv := server(t, &log, map[string]func(http.ResponseWriter, seen){
		"GET /api/v1/scoreboard": reply(`{"success":true,"data":[
			{"pos":1,"account_id":1,"account_type":"team","name":"A","score":500},
			{"pos":2,"account_id":2,"account_type":"team","name":"B","score":300},
			{"pos":3,"account_id":3,"account_type":"team","name":"C","score":100}]}`),
	})
	d := newDriver(t, srv, map[string]string{"CTFD_TOKEN": "tok"})
	sb, err := d.Scoreboard(context.Background(), ctf.ScoreboardQuery{Limit: 1, Offset: 1})
	if err != nil || sb.Total != 3 || len(sb.Entries) != 1 || sb.Entries[0].Name != "B" || sb.Entries[0].Position != 2 {
		t.Fatalf("got %+v %v", sb, err)
	}
	dr, _ := d.PrepareDownload(context.Background(), "/files/a.zip")
	if dr.Headers["Authorization"] != "Token tok" {
		t.Fatalf("same-origin header missing: %+v", dr)
	}
	dr, _ = d.PrepareDownload(context.Background(), "https://cdn.example/a.zip")
	if len(dr.Headers) != 0 {
		t.Fatalf("leaked auth cross-origin: %+v", dr)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, vals := range []map[string]string{
		{"CTFD_URL": "https://x"},
		{"CTFD_TOKEN": "t"},
		{"CTFD_URL": "https://x", "CTFD_TOKEN": "t", "CTFD_AUTH_MODE": "bogus"},
	} {
		if _, err := New(&driver.Env{Config: &config.Config{Platform: "ctfd", Values: vals}}); ctf.KindOf(err) != ctf.KindConfig {
			t.Errorf("%v: got %v", vals, err)
		}
	}
}
