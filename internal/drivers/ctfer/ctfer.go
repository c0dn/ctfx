// Package ctfer implements the "CTFer · Forensic Operations" platform: a
// bespoke React/Flask forensics-exercise app that is not stock CTFd. It has no
// /api/v1; findings live under /api/ui/* and flags are submitted with a native
// form POST to /challenge/<id>/submit. Auth is a Flask session cookie obtained
// by username/password login (or a pasted cookie). The CSRF token and the
// submit verdict both travel inside the signed session cookie, so this driver
// reads them straight out of the cookie rather than scraping the page.
package ctfer

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

var Spec = driver.Spec{
	Name:        "ctfer",
	DisplayName: "CTFer Forensic Operations",
	Description: "Bespoke forensics-exercise platform (CTFer): /api/ui findings, form-POST flag submit, Flask session auth",
	Kind:        "builtin",
	Example: `# CTFer (Forensic Operations) profile for ctfx
CTFX_PLATFORM="ctfer"
CTFER_URL="https://ctf.example.local"
# Log in with your account (recommended for long-running use):
CTFER_USERNAME=""
CTFER_PASSWORD=""
# ...or paste a browser session cookie value instead of username/password:
# CTFER_SESSION_COOKIE=""            # the ctfer_*_session cookie value
# CTFER_SESSION_COOKIE_NAME=""       # defaults to the app's *_session cookie
CTFER_VERIFY_SSL="true"
`,
	New:    New,
	Detect: Detect,
}

// Detect recognizes a CTFer instance from its login shell: a React SPA titled
// "CTFer" with a csrf-token meta tag, served by the Flask backend.
func Detect(ctx context.Context, c *http.Client, rawURL string) (*driver.Detection, bool) {
	base, err := core.NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, false
	}
	resp, err := core.Do(ctx, c, core.Request{URL: base + "/login"})
	if err != nil || resp.Status != 200 {
		return nil, false
	}
	body := string(resp.Body)
	if strings.Contains(body, `name="csrf-token"`) &&
		(strings.Contains(body, "CTFer") || strings.Contains(body, "/static/react/app.js")) {
		return &driver.Detection{BaseURL: base}, true
	}
	return nil, false
}

// Driver talks to one CTFer instance over an authenticated session.
type Driver struct {
	ctf.Unsupported
	client     *http.Client
	base       string
	baseURL    *url.URL
	username   string
	password   string
	cookie     string // pasted session cookie value (session mode)
	cookieName string // session cookie name (auto-detected when empty)
	authed     bool
}

// New builds a CTFer driver from env. The shared client is given a cookie jar
// and stops at redirects, so the signed session cookie (and the submit verdict
// flash it carries) is captured from each 302 instead of being lost.
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	base, err := core.NormalizeBaseURL(c.Get("URL"))
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFER_URL is missing or invalid; set it in %s or the environment", c.Source)
	}
	bu, err := url.Parse(base)
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFER_URL is not a valid URL: %v", err)
	}
	d := &Driver{
		base:       base,
		baseURL:    bu,
		username:   c.Get("USERNAME"),
		password:   c.Get("PASSWORD"),
		cookie:     c.Get("SESSION_COOKIE"),
		cookieName: c.Get("SESSION_COOKIE_NAME"),
	}
	if (d.username == "") != (d.password == "") {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFer needs both CTFER_USERNAME and CTFER_PASSWORD, or neither")
	}
	if d.username == "" && d.cookie == "" {
		return nil, ctf.Errorf(ctf.KindConfig, "CTFer needs CTFER_USERNAME + CTFER_PASSWORD or CTFER_SESSION_COOKIE")
	}
	// A private client: same transport/timeout as the shared one, but with a
	// jar (so cookies persist and survive redirects) and no redirect following
	// (so a 302's Set-Cookie is readable).
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	d.client = &http.Client{
		Transport:     env.Client.Transport,
		Timeout:       env.Client.Timeout,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return d, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Team: true, Hints: true}
}

// --- HTTP helpers ------------------------------------------------------------

func (d *Driver) url(path string) string {
	u, _ := core.JoinURL(d.base+"/", strings.TrimLeft(path, "/"))
	return u
}

func (d *Driver) get(ctx context.Context, path string) (*core.Response, error) {
	return core.Do(ctx, d.client, core.Request{URL: d.url(path), Headers: map[string]string{"Accept": "application/json"}})
}

func (d *Driver) postForm(ctx context.Context, path string, form url.Values) (*core.Response, error) {
	return core.Do(ctx, d.client, core.Request{
		Method:  http.MethodPost,
		URL:     d.url(path),
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
		Body:    strings.NewReader(form.Encode()),
	})
}

// apiJSON GETs an /api/ui/* endpoint and decodes the JSON body. A 401 is an
// auth error; other non-2xx are remote errors.
func (d *Driver) apiJSON(ctx context.Context, path string, out any) error {
	if err := d.ensureAuth(ctx); err != nil {
		return err
	}
	resp, err := d.get(ctx, path)
	if err != nil {
		return err
	}
	if resp.Status == 401 {
		return ctf.Errorf(ctf.KindAuth, "CTFer authentication required for %s (session expired?)", path)
	}
	if resp.Status >= 400 {
		return core.StatusError(resp.Status, "CTFer "+path, core.Truncate(string(resp.Body), 200))
	}
	if out != nil && !resp.JSON(out) {
		return ctf.Errorf(ctf.KindRemote, "CTFer returned non-JSON for %s (wrong URL, or a login page?)", path)
	}
	return nil
}

// --- session cookie plumbing -------------------------------------------------

// sessionState is the decoded, unverified payload of a Flask session cookie.
// We only read it (for the CSRF token and flashed submit verdicts); we never
// forge it, so the signing secret is not needed.
type sessionState struct {
	CSRF    string
	UserID  int
	Flashes [][2]string // {category, message}
}

// decodeFlaskSession decodes a Flask itsdangerous session cookie without its
// secret: "[.]base64url(payload).timestamp.signature", payload zlib-compressed
// when the whole value starts with a dot.
func decodeFlaskSession(raw string) (sessionState, bool) {
	var st sessionState
	if raw == "" {
		return st, false
	}
	compressed := strings.HasPrefix(raw, ".")
	if compressed {
		raw = raw[1:]
	}
	seg := raw
	if i := strings.IndexByte(seg, '.'); i >= 0 {
		seg = seg[:i]
	}
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		if data, err = base64.URLEncoding.DecodeString(seg); err != nil {
			return st, false
		}
	}
	if compressed {
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return st, false
		}
		if data, err = io.ReadAll(zr); err != nil {
			return st, false
		}
	}
	var p struct {
		CSRF    string            `json:"csrf"`
		UserID  int               `json:"user_id"`
		Flashes []json.RawMessage `json:"_flashes"`
	}
	if json.Unmarshal(data, &p) != nil {
		return st, false
	}
	st.CSRF, st.UserID = p.CSRF, p.UserID
	for _, raw := range p.Flashes {
		// Flask tags a (category, message) tuple as {" t": ["error", "..."]}.
		var tagged map[string][]string
		if json.Unmarshal(raw, &tagged) == nil {
			if tup, ok := tagged[" t"]; ok && len(tup) == 2 {
				st.Flashes = append(st.Flashes, [2]string{tup[0], tup[1]})
				continue
			}
		}
		var tup []string
		if json.Unmarshal(raw, &tup) == nil && len(tup) == 2 {
			st.Flashes = append(st.Flashes, [2]string{tup[0], tup[1]})
		}
	}
	return st, true
}

// sessionCookie returns the current session cookie value from the jar.
func (d *Driver) sessionCookie() string {
	for _, c := range d.client.Jar.Cookies(d.baseURL) {
		if d.cookieName != "" {
			if c.Name == d.cookieName {
				return c.Value
			}
			continue
		}
		if strings.HasSuffix(c.Name, "_session") || c.Name == "session" {
			d.cookieName = c.Name
			return c.Value
		}
	}
	return ""
}

// csrf reads the current CSRF token out of the session cookie. CTFer rotates it
// on every response, so it must be re-read immediately before each mutation.
func (d *Driver) csrf() string {
	st, _ := decodeFlaskSession(d.sessionCookie())
	return st.CSRF
}

func (d *Driver) seedCookie(value string) {
	if d.cookieName == "" {
		d.cookieName = "session"
	}
	d.client.Jar.SetCookies(d.baseURL, []*http.Cookie{{Name: d.cookieName, Value: value, Path: "/"}})
}

// --- auth --------------------------------------------------------------------

// ensureAuth establishes a session once. Password mode performs the login form
// flow; session mode seeds the pasted cookie. Either way it verifies the
// session with /api/ui/context.
func (d *Driver) ensureAuth(ctx context.Context) error {
	if d.authed {
		return nil
	}
	// Prime the jar with a session cookie (and its name) from the login shell.
	if _, err := d.get(ctx, "/login"); err != nil {
		return err
	}
	switch {
	case d.cookie != "":
		d.seedCookie(d.cookie)
	case d.username != "":
		form := url.Values{"username": {d.username}, "password": {d.password}, "csrf": {d.csrf()}}
		resp, err := d.postForm(ctx, "/login", form)
		if err != nil {
			return err
		}
		if resp.Status >= 400 && resp.Status != 302 {
			return core.StatusError(resp.Status, "CTFer login", core.Truncate(string(resp.Body), 200))
		}
		if st, ok := decodeFlaskSession(d.sessionCookie()); ok {
			for _, f := range st.Flashes {
				if f[0] == "error" {
					return ctf.Errorf(ctf.KindAuth, "CTFer login rejected: %s", f[1])
				}
			}
		}
	}
	// Confirm the session is actually authenticated.
	var cx struct {
		User struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	resp, err := d.get(ctx, "/api/ui/context")
	if err != nil {
		return err
	}
	if resp.Status == 401 || !resp.JSON(&cx) || cx.User.Username == "" {
		if d.cookie != "" {
			return ctf.Errorf(ctf.KindAuth, "CTFer session cookie is not valid (check CTFER_SESSION_COOKIE / _NAME)")
		}
		return ctf.Errorf(ctf.KindAuth, "CTFer login failed: check CTFER_USERNAME and CTFER_PASSWORD")
	}
	d.authed = true
	return nil
}

// --- challenges --------------------------------------------------------------

// investigationChallenge is one finding in the /api/ui/investigation list.
type investigationChallenge struct {
	ID                int     `json:"id"`
	Name              string  `json:"name"`
	Category          string  `json:"category"`
	Difficulty        string  `json:"difficulty"`
	Domain            string  `json:"domain"`
	Value             float64 `json:"value"`
	ProjectedPoints   float64 `json:"projected_points"`
	Solved            bool    `json:"solved"`
	SolveCount        int     `json:"solve_count"`
	Attempts          int     `json:"attempts"`
	MaxAttempts       int     `json:"max_attempts"`
	RemainingAttempts int     `json:"remaining_attempts"`
	Locked            bool    `json:"locked"`
	Slug              string  `json:"slug"`
	Order             int     `json:"order"`
}

func (c investigationChallenge) toChallenge() ctf.Challenge {
	pts := c.Value
	solves := c.SolveCount
	ch := ctf.Challenge{
		ID:       strconv.Itoa(c.ID),
		Name:     c.Name,
		Category: c.Category,
		Points:   &pts,
		Solved:   c.Solved,
		Solves:   &solves,
		Extra: map[string]any{
			"difficulty":         c.Difficulty,
			"domain":             c.Domain,
			"projected_points":   c.ProjectedPoints,
			"max_attempts":       c.MaxAttempts,
			"remaining_attempts": c.RemainingAttempts,
			"attempts":           c.Attempts,
			"locked":             c.Locked,
			"slug":               c.Slug,
		},
	}
	return ch
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	var payload struct {
		Challenges []investigationChallenge `json:"challenges"`
	}
	if err := d.apiJSON(ctx, "/api/ui/investigation", &payload); err != nil {
		return nil, err
	}
	out := make([]ctf.Challenge, 0, len(payload.Challenges))
	for _, c := range payload.Challenges {
		out = append(out, c.toChallenge())
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := payload.Challenges[i], payload.Challenges[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		return a.Value < b.Value
	})
	return out, nil
}

// challengeDetail is the /api/ui/challenge/<id> response.
type challengeDetail struct {
	ID                int     `json:"id"`
	Name              string  `json:"name"`
	Category          string  `json:"category"`
	Difficulty        string  `json:"difficulty"`
	Description       string  `json:"description"`
	Value             float64 `json:"value"`
	ProjectedPoints   float64 `json:"projected_points"`
	Solved            bool    `json:"solved"`
	Locked            bool    `json:"locked"`
	MaxAttempts       int     `json:"max_attempts"`
	RemainingAttempts int     `json:"remaining_attempts"`
	SubmissionExample string  `json:"submission_example"`
	Slug              string  `json:"slug"`
	Hints             []struct {
		ID       int     `json:"id"`
		Cost     float64 `json:"cost"`
		Unlocked bool    `json:"unlocked"`
		Content  *string `json:"content"`
	} `json:"hints"`
}

func numericID(id, what string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(id))
	if err != nil || n <= 0 {
		return 0, ctf.Errorf(ctf.KindUsage, "CTFer %s must be a positive integer, got %q", what, id)
	}
	return n, nil
}

func (d *Driver) getDetail(ctx context.Context, id int) (*challengeDetail, error) {
	var det challengeDetail
	if err := d.apiJSON(ctx, fmt.Sprintf("/api/ui/challenge/%d", id), &det); err != nil {
		return nil, err
	}
	return &det, nil
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	n, err := numericID(id, "challenge ID")
	if err != nil {
		return nil, err
	}
	det, err := d.getDetail(ctx, n)
	if err != nil {
		return nil, err
	}
	pts := det.Value
	ch := ctf.Challenge{
		ID:          strconv.Itoa(det.ID),
		Name:        det.Name,
		Category:    det.Category,
		Points:      &pts,
		Solved:      det.Solved,
		Description: det.Description,
		Extra: map[string]any{
			"difficulty":         det.Difficulty,
			"projected_points":   det.ProjectedPoints,
			"max_attempts":       det.MaxAttempts,
			"remaining_attempts": det.RemainingAttempts,
			"submission_example": det.SubmissionExample,
			"slug":               det.Slug,
			"locked":             det.Locked,
		},
	}
	if ch.ID == "" {
		ch.ID = strconv.Itoa(n)
	}
	ch.Hints = det.hints()
	return &ch, nil
}

func (det *challengeDetail) hints() []ctf.Hint {
	var out []ctf.Hint
	for _, h := range det.Hints {
		out = append(out, ctf.Hint{
			ID:      strconv.Itoa(h.ID),
			Cost:    h.Cost,
			Locked:  !h.Unlocked,
			Content: h.Content,
		})
	}
	return out
}

func (d *Driver) Hints(ctx context.Context, challengeID string) ([]ctf.Hint, error) {
	n, err := numericID(challengeID, "challenge ID")
	if err != nil {
		return nil, err
	}
	det, err := d.getDetail(ctx, n)
	if err != nil {
		return nil, err
	}
	if h := det.hints(); h != nil {
		return h, nil
	}
	return []ctf.Hint{}, nil
}

// --- submit ------------------------------------------------------------------

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	n, err := numericID(id, "challenge ID")
	if err != nil {
		return nil, err
	}
	if err := d.ensureAuth(ctx); err != nil {
		return nil, err
	}
	form := url.Values{"csrf": {d.csrf()}, "flag": {flag}}
	resp, err := d.postForm(ctx, fmt.Sprintf("/challenge/%d/submit", n), form)
	if err != nil {
		return nil, err
	}
	res := &ctf.SubmitResult{ChallengeID: strconv.Itoa(n), HTTPStatus: resp.Status}
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "CTFer authentication required (session expired?)")
	}
	if resp.Status == 400 {
		// Most often a stale/invalid CSRF token.
		return nil, ctf.Errorf(ctf.KindRemote, "CTFer submit rejected (%d): %s", resp.Status, core.Truncate(string(resp.Body), 160))
	}
	// The verdict is flashed into the session cookie set by the 302 response.
	var flash [2]string
	if st, ok := decodeFlaskSession(d.sessionCookie()); ok && len(st.Flashes) > 0 {
		flash = st.Flashes[len(st.Flashes)-1]
		res.Message, res.ResponseKind = flash[1], flash[0]
	}
	// The server's flashed verdict is authoritative for everything except a
	// plain "incorrect"/"error". For those, cross-check the finding's solved
	// state so a true solve with unexpected flash wording still reads correct.
	res.Status = classifyFlash(flash[0], flash[1], resp.Status)
	switch res.Status {
	case ctf.StatusIncorrect, ctf.StatusError:
		if det, derr := d.getDetail(ctx, n); derr == nil && det.Solved {
			res.Status = ctf.StatusCorrect
			if res.Message == "" {
				res.Message = "correct"
			}
		}
	}
	res.Correct = res.Status == ctf.StatusCorrect
	return res, nil
}

// classifyFlash maps a flashed (category, message) verdict to a ctf status.
func classifyFlash(category, message string, status int) string {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "not open"), strings.Contains(m, "not started"),
		strings.Contains(m, "not yet"), strings.Contains(m, "draft"):
		return ctf.StatusNotStarted
	case strings.Contains(m, "ended"), strings.Contains(m, "closed"), strings.Contains(m, "over"):
		return ctf.StatusEnded
	case strings.Contains(m, "already"), strings.Contains(m, "confirmed"),
		strings.Contains(m, "no attempt was consumed"):
		return ctf.StatusAlreadySolved
	case strings.Contains(m, "too many"), strings.Contains(m, "cooldown"),
		strings.Contains(m, "rate"), strings.Contains(m, "wait"),
		strings.Contains(m, "no attempts"), strings.Contains(m, "maximum"),
		strings.Contains(m, "exhausted"), status == 429:
		return ctf.StatusRateLimited
	// "incorrect"/"invalid" must be tested before "correct" (substring trap).
	case strings.Contains(m, "incorrect"), strings.Contains(m, "invalid"),
		strings.Contains(m, "wrong"), strings.Contains(m, "not accepted"),
		strings.Contains(m, "try again"):
		return ctf.StatusIncorrect
	case strings.Contains(m, "correct"), strings.Contains(m, "solved"),
		strings.Contains(m, "accepted"), strings.Contains(m, "nice"),
		(category == "success" && message != ""):
		return ctf.StatusCorrect
	case category == "error":
		return ctf.StatusIncorrect
	case message == "":
		return ctf.StatusError
	default:
		return ctf.StatusIncorrect
	}
}

// --- solves, scoreboard, team ------------------------------------------------

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	var payload struct {
		Challenges []investigationChallenge `json:"challenges"`
	}
	if err := d.apiJSON(ctx, "/api/ui/investigation", &payload); err != nil {
		return nil, err
	}
	var out []ctf.Solve
	for _, c := range payload.Challenges {
		if !c.Solved {
			continue
		}
		pts := c.Value
		out = append(out, ctf.Solve{
			ChallengeID: strconv.Itoa(c.ID),
			Name:        c.Name,
			Category:    c.Category,
			Points:      &pts,
		})
	}
	return out, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	var payload struct {
		Standings []struct {
			Name       string  `json:"name"`
			Score      float64 `json:"score"`
			Playtester bool    `json:"playtester"`
		} `json:"standings"`
	}
	if err := d.apiJSON(ctx, "/api/scoreboard", &payload); err != nil {
		return nil, err
	}
	sb := &ctf.Scoreboard{Total: len(payload.Standings)}
	for i, s := range payload.Standings {
		e := ctf.ScoreEntry{Position: i + 1, Name: s.Name, Score: s.Score, AccountType: "team"}
		if s.Playtester {
			e.Extra = map[string]any{"playtester": true}
		}
		sb.Entries = append(sb.Entries, e)
	}
	sb.Entries = window(sb.Entries, q)
	return sb, nil
}

func window(e []ctf.ScoreEntry, q ctf.ScoreboardQuery) []ctf.ScoreEntry {
	if q.Offset >= len(e) {
		return []ctf.ScoreEntry{}
	}
	e = e[q.Offset:]
	if q.Limit > 0 && q.Limit < len(e) {
		e = e[:q.Limit]
	}
	return e
}

func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	var cx struct {
		User struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
			Team     string `json:"team"`
			IsAdmin  bool   `json:"is_admin"`
		} `json:"user"`
	}
	if err := d.apiJSON(ctx, "/api/ui/context", &cx); err != nil {
		return nil, err
	}
	ts := &ctf.TeamStatus{User: &ctf.Account{ID: strconv.Itoa(cx.User.ID), Name: cx.User.Username}}
	var tm struct {
		Team struct {
			ID         int      `json:"id"`
			Name       string   `json:"name"`
			Members    []string `json:"members"`
			InviteCode string   `json:"invite_code"`
		} `json:"team"`
	}
	if err := d.apiJSON(ctx, "/api/ui/team", &tm); err != nil {
		ts.TeamError = err.Error()
		return ts, nil
	}
	if tm.Team.Name != "" {
		team := &ctf.Account{ID: strconv.Itoa(tm.Team.ID), Name: tm.Team.Name}
		for _, m := range tm.Team.Members {
			team.Members = append(team.Members, ctf.Member{Name: m})
		}
		ts.Team = team
	}
	return ts, nil
}
