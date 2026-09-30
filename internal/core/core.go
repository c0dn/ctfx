// Package core holds the platform-independent plumbing every driver shares:
// the HTTP client, JSON helpers, and safe attachment downloads.
package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/c0dn/ctfx/pkg/ctf"
	"github.com/imroc/req/v3"
)

// DefaultUserAgent is sent when impersonation is off and no override is set.
var DefaultUserAgent = "ctfx"

var impersonateUA = map[string]string{
	"chrome":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
	"firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
	"safari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
}

// ClientOptions configure the shared HTTP client.
type ClientOptions struct {
	Verify      bool   // TLS certificate verification
	Impersonate string // "", "off", "chrome", "firefox", "safari", "auto"
	UserAgent   string // overrides the default User-Agent
	Cookies     string // extra Cookie header on every request (eg cf_clearance=...)
}

// NewClient builds the shared HTTP client. With Impersonate set to a browser
// name it mimics that browser's TLS + HTTP/2 + header-order fingerprint (via
// req/utls) to get past passive bot screening; otherwise it is a plain
// net/http client. UserAgent and Cookies apply in both modes. Impersonation
// does not defeat JavaScript challenges (Turnstile): for those, copy a real
// cf_clearance cookie into Cookies with a matching UserAgent.
func NewClient(o ClientOptions) *http.Client {
	imp := strings.ToLower(strings.TrimSpace(o.Impersonate))
	ua := o.UserAgent
	if imp == "" || imp == "off" || imp == "none" || imp == "false" {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if !o.Verify {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed CTF hosts
		}
		if ua == "" {
			ua = DefaultUserAgent
		}
		return &http.Client{Timeout: 60 * time.Second, Transport: &defaultHeaders{next: tr, ua: ua, cookies: o.Cookies}}
	}
	if imp == "auto" {
		imp = "chrome"
	}
	rc := req.C()
	if !o.Verify {
		rc.EnableInsecureSkipVerify()
	}
	switch imp {
	case "firefox":
		rc.ImpersonateFirefox()
	case "safari":
		rc.ImpersonateSafari()
	default: // chrome, and any unknown name
		rc.ImpersonateChrome()
		imp = "chrome"
	}
	rc.SetTimeout(60 * time.Second)
	hc := rc.GetClient()
	if ua == "" {
		ua = impersonateUA[imp]
	}
	// req applies its fingerprint (TLS, HTTP/2, header order) at the transport
	// level, which survives GetClient(); the browser header *values* live on
	// req.Request, so we inject a consistent set here instead.
	hc.Transport = &defaultHeaders{next: hc.Transport, ua: ua, cookies: o.Cookies, extra: browserHeaders(imp)}
	return hc
}

func browserHeaders(imp string) map[string]string {
	base := map[string]string{"Accept-Language": "en-US,en;q=0.9"}
	if imp == "chrome" {
		base["sec-ch-ua"] = `"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`
		base["sec-ch-ua-mobile"] = "?0"
		base["sec-ch-ua-platform"] = `"Linux"`
	}
	return base
}

// defaultHeaders fills the User-Agent, browser hint headers, and a persistent
// Cookie only when the caller has not already set them.
type defaultHeaders struct {
	next    http.RoundTripper
	ua      string
	cookies string
	extra   map[string]string
}

func (t *defaultHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.ua != "" && r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", t.ua)
	}
	for k, v := range t.extra {
		if r.Header.Get(k) == "" {
			r.Header.Set(k, v)
		}
	}
	if t.cookies != "" {
		if existing := r.Header.Get("Cookie"); existing != "" {
			r.Header.Set("Cookie", existing+"; "+t.cookies)
		} else {
			r.Header.Set("Cookie", t.cookies)
		}
	}
	return t.next.RoundTrip(r)
}

// Response is a fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	URL    *url.URL // final URL after redirects
}

// JSON decodes the body into v; it reports whether decoding succeeded.
func (r *Response) JSON(v any) bool {
	return len(r.Body) > 0 && json.Unmarshal(r.Body, v) == nil
}

// Request describes one HTTP call.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	JSON    any       // encoded as the body when non-nil
	Body    io.Reader // raw body, used when JSON is nil
}

// Do performs req and reads the whole body. Network failures are remote errors.
func Do(ctx context.Context, c *http.Client, req Request) (*Response, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	body := req.Body
	if req.JSON != nil {
		b, err := json.Marshal(req.JSON)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, ctf.Errorf(ctf.KindUsage, "bad request URL %q: %v", req.URL, err)
	}
	if req.JSON != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	resp, err := c.Do(hr)
	if err != nil {
		return nil, ctf.Errorf(ctf.KindRemote, "%s %s: %v", method, redactURL(req.URL), err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ctf.Errorf(ctf.KindRemote, "reading %s: %v", redactURL(req.URL), err)
	}
	if err := antibot(resp.StatusCode, resp.Header, b); err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b, URL: resp.Request.URL}, nil
}

// antibot reports a helpful error when a response is a Cloudflare-style
// interstitial rather than a real API answer. It matches only clear challenge
// markers so a plain 403 from the platform is left to the driver.
func antibot(status int, h http.Header, body []byte) error {
	if status != 403 && status != 503 {
		return nil
	}
	if h.Get("cf-mitigated") == "challenge" ||
		bytes.Contains(body, []byte("cdn-cgi/challenge-platform")) ||
		bytes.Contains(body, []byte("Just a moment")) {
		return ctf.Errorf(ctf.KindAuth,
			"blocked by an anti-bot challenge (Cloudflare); set CTFX_IMPERSONATE=chrome, and if that is not enough copy a browser cf_clearance into CTFX_COOKIES with a matching CTFX_USER_AGENT")
	}
	return nil
}

// redactURL drops the query string, which may carry tokens.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}

// JoinURL resolves ref against base (base is treated as a directory).
func JoinURL(base, ref string) (string, error) {
	b, err := url.Parse(strings.TrimRight(base, "/") + "/")
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	out := b.ResolveReference(r)
	if out.Scheme != "http" && out.Scheme != "https" {
		return "", ctf.Errorf(ctf.KindUsage, "unsupported URL scheme %q", out.Scheme)
	}
	return out.String(), nil
}

// SameOrigin reports whether a and b share scheme, host, and port.
func SameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}

// NormalizeBaseURL trims whitespace and trailing slashes and validates scheme.
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ctf.Errorf(ctf.KindConfig, "invalid platform URL %q", raw)
	}
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

// FilenameFromURL returns the last path segment, or "download".
func FilenameFromURL(raw string) string {
	u, err := url.Parse(raw)
	p := raw
	if err == nil {
		p = u.Path
	}
	name := path.Base(strings.TrimRight(p, "/"))
	if dec, err := url.PathUnescape(name); err == nil {
		name = dec
	}
	return SanitizeFilename(name)
}

// SanitizeFilename reduces a name to a safe single path component.
func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimSpace(path.Base(name))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`:*?"<>|`, r) {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." || name == "/" {
		return "download"
	}
	return name
}

// FilenameFromDisposition extracts a sanitized filename from a
// Content-Disposition header, or "".
func FilenameFromDisposition(h string) string {
	if h == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(h)
	if err != nil || params["filename"] == "" {
		return ""
	}
	return SanitizeFilename(params["filename"])
}

// InsideRoot reports whether target is root or below it.
func InsideRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Downloaded describes a saved attachment.
type Downloaded struct {
	URL       string `json:"url"`
	Filename  string `json:"filename"`
	SavedTo   string `json:"saved_to"`
	SizeBytes int    `json:"size_bytes"`
	Skipped   bool   `json:"skipped,omitempty"`
}

// SaveOptions controls where a download lands.
type SaveOptions struct {
	Root string // writes must stay inside Root
	Dest string // file or directory; directory when it ends in / or has no extension
	Name string // preferred filename when Dest is a directory
	// SkipExisting leaves an existing file untouched and reports Skipped.
	SkipExisting bool
}

// Download fetches dr and writes it according to opts.
func Download(ctx context.Context, c *http.Client, dr *ctf.DownloadRequest, opts SaveOptions) (*Downloaded, error) {
	target, err := resolveDest(opts, opts.Name)
	if err == nil && opts.SkipExisting && opts.Name != "" {
		if st, statErr := os.Stat(target); statErr == nil && !st.IsDir() {
			return &Downloaded{URL: redactURL(dr.URL), Filename: filepath.Base(target), SavedTo: target, SizeBytes: int(st.Size()), Skipped: true}, nil
		}
	}
	resp, err := Do(ctx, c, Request{URL: dr.URL, Headers: dr.Headers})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Status == 401 || resp.Status == 403:
		return nil, ctf.Errorf(ctf.KindAuth, "download denied (HTTP %d): %s", resp.Status, redactURL(dr.URL))
	case resp.Status == 404:
		return nil, ctf.Errorf(ctf.KindNotFound, "file not found: %s", redactURL(dr.URL))
	case resp.Status >= 400:
		return nil, ctf.Errorf(ctf.KindRemote, "download failed (HTTP %d): %s", resp.Status, redactURL(dr.URL))
	}
	name := opts.Name
	if name == "" {
		name = FilenameFromDisposition(resp.Header.Get("Content-Disposition"))
	}
	if name == "" {
		name = FilenameFromURL(dr.URL)
	}
	target, err = resolveDest(opts, name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(target, resp.Body, 0o644); err != nil {
		return nil, err
	}
	return &Downloaded{URL: redactURL(dr.URL), Filename: filepath.Base(target), SavedTo: target, SizeBytes: len(resp.Body)}, nil
}

func resolveDest(opts SaveOptions, name string) (string, error) {
	name = SanitizeFilename(name)
	dest := opts.Dest
	if dest == "" {
		dest = "." + string(filepath.Separator)
	}
	asDir := strings.HasSuffix(dest, "/") || strings.HasSuffix(dest, string(filepath.Separator)) || filepath.Ext(dest) == ""
	if st, err := os.Stat(dest); err == nil {
		asDir = st.IsDir()
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	if asDir {
		abs = filepath.Join(abs, name)
	}
	root, _ := filepath.Abs(opts.Root)
	if !InsideRoot(root, abs) {
		return "", ctf.Errorf(ctf.KindUsage, "refusing to write outside the workspace %s: %s", root, abs)
	}
	return abs, nil
}

// Helpers for loosely typed JSON payloads.

// Str returns v as a string when it is a string or number, else "".
func Str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// Num returns v as a float when it is a finite number or numeric string.
func Num(v any) *float64 {
	switch t := v.(type) {
	case float64:
		return &t
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
			return &f
		}
	}
	return nil
}

// Int returns v as an int pointer when numeric.
func Int(v any) *int {
	if f := Num(v); f != nil {
		i := int(*f)
		return &i
	}
	return nil
}

// Obj returns v as a JSON object, or an empty map.
func Obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// Arr returns v as a JSON array, or nil.
func Arr(v any) []any {
	a, _ := v.([]any)
	return a
}

// Deref returns *f or 0.
func Deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// Truncate shortens s for error messages.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// StatusError maps a non-2xx status to a classified error.
func StatusError(status int, what, msg string) error {
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", status)
	}
	switch status {
	case 401:
		return ctf.Errorf(ctf.KindAuth, "%s: authentication failed: %s", what, msg)
	case 403:
		return ctf.Errorf(ctf.KindAuth, "%s: access denied: %s", what, msg)
	case 404:
		return ctf.Errorf(ctf.KindNotFound, "%s: not found: %s", what, msg)
	}
	return ctf.Errorf(ctf.KindRemote, "%s: %s", what, msg)
}
