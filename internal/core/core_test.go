package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0dn/ctfx/pkg/ctf"
)

func TestNewClientStdlibUAAndCookies(t *testing.T) {
	var gotUA, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotCookie = r.Header.Get("User-Agent"), r.Header.Get("Cookie")
	}))
	defer srv.Close()
	c := NewClient(ClientOptions{Verify: true, UserAgent: "custom-ua", Cookies: "cf_clearance=abc"})
	if _, err := Do(context.Background(), c, Request{URL: srv.URL, Headers: map[string]string{"Cookie": "session=x"}}); err != nil {
		t.Fatal(err)
	}
	if gotUA != "custom-ua" {
		t.Errorf("UA = %q", gotUA)
	}
	if gotCookie != "session=x; cf_clearance=abc" {
		t.Errorf("cookie = %q", gotCookie)
	}
}

func TestNewClientImpersonateChrome(t *testing.T) {
	var gotUA, gotCHUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotCHUA = r.Header.Get("User-Agent"), r.Header.Get("Sec-Ch-Ua")
	}))
	defer srv.Close()
	c := NewClient(ClientOptions{Verify: false, Impersonate: "chrome"})
	if _, err := Do(context.Background(), c, Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if gotUA == "" || gotUA == "ctfx" || !strings.Contains(strings.ToLower(gotUA), "chrome") {
		t.Errorf("expected a Chrome UA, got %q", gotUA)
	}
	if gotCHUA == "" {
		t.Error("expected sec-ch-ua client hint to be sent")
	}
}

func TestAntibotChallengeDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`<html><head><title>Just a moment...</title></head></html>`))
	}))
	defer srv.Close()
	_, err := Do(context.Background(), NewClient(ClientOptions{Verify: true}), Request{URL: srv.URL})
	if ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("expected anti-bot auth error, got %v", err)
	}
	// A plain 403 without challenge markers is left to the driver, not intercepted.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer plain.Close()
	resp, err := Do(context.Background(), NewClient(ClientOptions{Verify: true}), Request{URL: plain.URL})
	if err != nil || resp.Status != 403 {
		t.Fatalf("plain 403 should pass through: resp=%v err=%v", resp, err)
	}
}

func TestJoinURL(t *testing.T) {
	cases := map[[2]string]string{
		{"https://x/api/v1/", "challenges"}:  "https://x/api/v1/challenges",
		{"https://x/sub", "/files/a?t=1"}:    "https://x/files/a?t=1",
		{"https://x/sub", "files/a"}:         "https://x/sub/files/a",
		{"https://x", "https://cdn.y/a.zip"}: "https://cdn.y/a.zip",
	}
	for in, want := range cases {
		got, err := JoinURL(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("JoinURL(%q,%q)=%q,%v want %q", in[0], in[1], got, err, want)
		}
	}
	if _, err := JoinURL("https://x", "file:///etc/passwd"); err == nil {
		t.Error("file scheme accepted")
	}
}

func TestFilenames(t *testing.T) {
	if got := FilenameFromURL("https://x/files/abc/chall%20v2.zip?token=1"); got != "chall v2.zip" {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"../../etc/passwd", "..", "", `a\..\b`} {
		if got := SanitizeFilename(bad); got == ".." || filepath.Base(got) != got || got == "" {
			t.Errorf("SanitizeFilename(%q)=%q", bad, got)
		}
	}
	if got := FilenameFromDisposition(`attachment; filename*=UTF-8''na%C3%AFve.bin`); got != "naïve.bin" {
		t.Errorf("got %q", got)
	}
	if got := FilenameFromDisposition(`attachment; filename="../x.txt"`); got != "x.txt" {
		t.Errorf("got %q", got)
	}
}

func TestDownloadStaysInRoot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token t" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="chal.bin"`)
		w.Write([]byte("abc"))
	}))
	defer srv.Close()
	root := t.TempDir()
	dr := &ctf.DownloadRequest{URL: srv.URL + "/f", Headers: map[string]string{"Authorization": "Token t"}}
	ctx := context.Background()

	d, err := Download(ctx, srv.Client(), dr, SaveOptions{Root: root, Dest: filepath.Join(root, "dist") + "/"})
	if err != nil || d.SavedTo != filepath.Join(root, "dist", "chal.bin") || d.SizeBytes != 3 {
		t.Fatalf("got %+v %v", d, err)
	}
	d, err = Download(ctx, srv.Client(), dr, SaveOptions{Root: root, Dest: filepath.Join(root, "dist") + "/", Name: "chal.bin", SkipExisting: true})
	if err != nil || !d.Skipped {
		t.Fatalf("expected skip, got %+v %v", d, err)
	}
	if _, err := Download(ctx, srv.Client(), dr, SaveOptions{Root: root, Dest: "/tmp/escape.txt"}); ctf.KindOf(err) != ctf.KindUsage {
		t.Fatalf("expected outside-root rejection, got %v", err)
	}
	if _, err := Download(ctx, srv.Client(), &ctf.DownloadRequest{URL: srv.URL}, SaveOptions{Root: root, Dest: root + "/"}); ctf.KindOf(err) != ctf.KindAuth {
		t.Fatalf("expected auth error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "download")); err == nil {
		t.Fatal("failed download wrote a file")
	}
}
