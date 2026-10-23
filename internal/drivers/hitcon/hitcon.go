// Package hitcon implements the HITCON CTF scoreboard (ctf20xx.hitcon.org): a
// bespoke Django + Alpine.js app behind Cloudflare.
//
// Scoreboard API, read from the site's dashboard.js / scoreboard.js:
//
//	GET  /dashboard/challenge_data      -> [{id,name,description,category,score,author,solved_times,solved,hint,is_opened,type,koh_score}]
//	GET  /dashboard/scoreboard_data     -> {teamstat:[{id,name,score,country_name,last_submit_time,solved_challenge}],challenges:{},last_update}
//	POST /dashboard/submit_flag         form flag=&id=, header X-CSRFToken -> {"result":"wrong"|"duplicated"|<correct>,"id":N}
//	                                    non-2xx carry {"detail":...}: 429 too fast, 403 contest not running
//	GET  /team/                         HTML: team name, rank, score, token, solved table
//
// Auth is the Django `sessionid` cookie. Login is behind Turnstile, so the
// cookie is copied from a logged-in browser. Cloudflare's managed challenge is
// passed by a Chrome TLS/HTTP2 fingerprint (no cf_clearance needed when this
// was written), so this driver impersonates Chrome unless told otherwise.
//
// Per-challenge instancers live on *.chal.hitconctf.com, outside Cloudflare,
// and authenticate with the team token. Each speaks its own protocol; see
// instancer.go.
package hitcon

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

var Spec = driver.Spec{
	Name:        "hitcon",
	DisplayName: "HITCON CTF",
	Description: "HITCON CTF scoreboard (Django, Cloudflare) with a browser sessionid cookie; per-challenge team-token instancers",
	Kind:        "builtin",
	Example: `# HITCON CTF profile for ctfx
CTFX_PLATFORM="hitcon"
HITCON_URL="https://ctf2026.hitcon.org"
# Django session cookie "sessionid" from a logged-in browser (DevTools >
# Application > Cookies > ctf2026.hitcon.org). Login needs Turnstile, so ctfx
# cannot log in by itself. Valid for about two weeks unless you log out.
HITCON_SESSIONID=""
# Team token shown on /team/; used only by the challenge instancers.
HITCON_TEAM_TOKEN=""
# Cloudflare is passed with a Chrome fingerprint. If it starts challenging,
# add the browser's cf_clearance with the exact browser User-Agent:
# HITCON_COOKIES="cf_clearance=..."
# HITCON_USER_AGENT="Mozilla/5.0 ..."
HITCON_IMPERSONATE="chrome"
# Optional instancer overrides, merged over the built-in table:
#   <challenge id>=<kind>@<base url>, separated by ";"  (kind: hostname|calc|vulcreator)
# HITCON_INSTANCERS="4=hostname@http://nsa.chal.hitconctf.com"
HITCON_VERIFY_SSL="true"
`,
	New:    New,
	Detect: Detect,
}

var hostRe = regexp.MustCompile(`^ctf\d{4}\.hitcon\.org$`)

// Detect recognizes a HITCON CTF scoreboard by host name. The site sits behind
// a Cloudflare challenge, so probing it would not be cheap or reliable.
func Detect(_ context.Context, _ *http.Client, rawURL string) (*driver.Detection, bool) {
	base, err := core.NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, false
	}
	u, err := url.Parse(base)
	if err != nil || !hostRe.MatchString(strings.ToLower(u.Hostname())) {
		return nil, false
	}
	return &driver.Detection{BaseURL: u.Scheme + "://" + u.Host}, true
}

// Driver talks to one HITCON scoreboard plus its instancers.
type Driver struct {
	ctf.Unsupported
	site       *http.Client // impersonating client with a cookie jar, no redirects
	inst       *http.Client // plain client for *.chal.hitconctf.com
	base       string
	baseURL    *url.URL
	session    string
	csrf       string
	teamToken  string
	instancers map[string]instancerConf
	seeded     bool
	root       string // workspace root, for persisted instancer sessions
	store      *cookieStore
}

// New builds the driver. It uses its own client: Chrome impersonation by
// default (the shared client is plain unless CTFX_IMPERSONATE is set).
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	imp := c.Get("IMPERSONATE")
	if imp == "" {
		imp = "chrome"
	}
	site := core.NewClient(core.ClientOptions{
		Verify:      c.Bool("VERIFY_SSL", true),
		Impersonate: imp,
		UserAgent:   c.Get("USER_AGENT"),
		Cookies:     c.Get("COOKIES"),
	})
	d, err := newDriver(c.Get, site, env.Client)
	if err != nil {
		return nil, err
	}
	d.root = c.Root
	return d, nil
}

func newDriver(get func(string) string, site, inst *http.Client) (*Driver, error) {
	base, err := core.NormalizeBaseURL(get("URL"))
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "HITCON_URL is missing or invalid (eg https://ctf2026.hitcon.org)")
	}
	bu, err := url.Parse(base)
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "HITCON_URL is not a valid URL: %v", err)
	}
	ins, err := parseInstancers(get("INSTANCERS"))
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	d := &Driver{
		site: &http.Client{
			Transport:     site.Transport,
			Timeout:       site.Timeout,
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		// Instancers can take a while (docker compose up) and answer /create
		// with a redirect whose Set-Cookie must be kept, so do not follow.
		inst: &http.Client{
			Transport:     inst.Transport,
			Timeout:       180 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base:       base,
		baseURL:    bu,
		session:    strings.TrimPrefix(get("SESSIONID"), "sessionid="),
		csrf:       get("CSRFTOKEN"),
		teamToken:  get("TEAM_TOKEN"),
		instancers: ins,
	}
	return d, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Team: true, Download: true, Hints: true, Instances: true}
}

// --- scoreboard HTTP ---------------------------------------------------------

func (d *Driver) seed() error {
	if d.session == "" {
		return ctf.Errorf(ctf.KindConfig, "HITCON needs HITCON_SESSIONID (the sessionid cookie from a logged-in browser)")
	}
	if !d.seeded {
		cs := []*http.Cookie{{Name: "sessionid", Value: d.session, Path: "/"}}
		if d.csrf != "" {
			cs = append(cs, &http.Cookie{Name: "csrftoken", Value: d.csrf, Path: "/"})
		}
		d.site.Jar.SetCookies(d.baseURL, cs)
		d.seeded = true
	}
	return nil
}

func (d *Driver) do(ctx context.Context, method, path string, headers map[string]string, body string) (*core.Response, error) {
	if err := d.seed(); err != nil {
		return nil, err
	}
	req := core.Request{Method: method, URL: d.base + path, Headers: headers}
	if body != "" {
		req.Body = strings.NewReader(body)
	}
	resp, err := core.Do(ctx, d.site, req)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 || (resp.Status == 302 && strings.Contains(resp.Header.Get("Location"), "/login")) {
		return nil, ctf.Errorf(ctf.KindAuth, "HITCON session is not logged in (HITCON_SESSIONID expired or wrong?)")
	}
	return resp, nil
}

func (d *Driver) getJSON(ctx context.Context, path string, out any) error {
	resp, err := d.do(ctx, http.MethodGet, path, map[string]string{"Accept": "application/json"}, "")
	if err != nil {
		return err
	}
	if resp.Status >= 300 {
		return core.StatusError(resp.Status, "HITCON "+path, core.Truncate(string(resp.Body), 200))
	}
	if !resp.JSON(out) {
		return ctf.Errorf(ctf.KindRemote, "HITCON returned non-JSON for %s", path)
	}
	return nil
}

func (d *Driver) getHTML(ctx context.Context, path string) (string, error) {
	resp, err := d.do(ctx, http.MethodGet, path, map[string]string{"Accept": "text/html"}, "")
	if err != nil {
		return "", err
	}
	if resp.Status >= 300 {
		return "", core.StatusError(resp.Status, "HITCON "+path, "")
	}
	return string(resp.Body), nil
}

// --- challenges --------------------------------------------------------------

type rawChallenge struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Score       float64 `json:"score"`
	Author      string  `json:"author"`
	SolvedTimes int     `json:"solved_times"`
	Solved      bool    `json:"solved"`
	Hint        []struct {
		Content    string  `json:"content"`
		PublicTime float64 `json:"public_time"`
	} `json:"hint"`
	IsOpened bool     `json:"is_opened"`
	Type     string   `json:"type"`
	KohScore *float64 `json:"koh_score"`
}

var (
	mdLinkRe  = regexp.MustCompile(`\[([^\]]*)\]\((https?://[^)\s]+|/[^)\s]+)\)`)
	ncRe      = regexp.MustCompile(`(?m)^\s*((?:nc|ncat|socat|ssh)\s+[^\n]+?)\s*$`)
	instRe    = regexp.MustCompile(`(?i)instancer:?\s*\[?(https?://[a-z0-9.-]+\.chal\.hitconctf\.com[^\s\])]*)`)
	anyURLRe  = regexp.MustCompile(`https?://[^\s\])>"']+`)
	fileExtRe = regexp.MustCompile(`(?i)\.(tar\.gz|tgz|tar|zip|7z|gz|xz|bz2|zst|bin|elf|exe|py|c|txt|pcap|pcapng|img|iso)$`)
)

func (d *Driver) toChallenge(r rawChallenge) ctf.Challenge {
	pts := r.Score
	solves := r.SolvedTimes
	ch := ctf.Challenge{
		ID:          strconv.Itoa(r.ID),
		Name:        r.Name,
		Category:    r.Category,
		Author:      r.Author,
		Points:      &pts,
		Solved:      r.Solved,
		Solves:      &solves,
		Description: r.Description,
		Extra:       map[string]any{"type": r.Type, "is_opened": r.IsOpened},
	}
	if r.KohScore != nil {
		ch.Extra["koh_score"] = *r.KohScore
	}
	for _, m := range mdLinkRe.FindAllStringSubmatch(r.Description, -1) {
		link := m[2]
		if strings.HasPrefix(link, "/") {
			link = d.base + link
		}
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		isAttach := strings.HasPrefix(u.Host, "ctf") && strings.Contains(u.Host, "attach")
		isStatic := core.SameOrigin(link, d.base) && strings.HasPrefix(u.Path, "/static/chall/")
		if isAttach || isStatic || (fileExtRe.MatchString(u.Path) && !strings.HasSuffix(u.Host, ".chal.hitconctf.com")) {
			name := core.FilenameFromURL(link)
			if name == "" {
				name = m[1]
			}
			ch.Files = append(ch.Files, ctf.File{Name: name, URL: link})
		}
	}
	if m := ncRe.FindStringSubmatch(r.Description); m != nil {
		ch.Connection = m[1]
	}
	if ic, ok := d.instancerFor(ch.ID, r.Description); ok {
		ch.Instance = &ctf.InstanceRef{Backend: ic.Kind, Slug: ch.ID}
		ch.Extra["instancer"] = ic.URL
		if ch.Connection == "" {
			ch.Connection = ic.URL
		}
	} else if ch.Connection == "" {
		// Bare challenge URLs (eg http://fastcoll.chal.hitconctf.com/).
		for _, u := range anyURLRe.FindAllString(r.Description, -1) {
			if strings.Contains(u, ".chal.hitconctf.com") {
				ch.Connection = strings.TrimRight(u, ".,")
				break
			}
		}
	}
	for i, h := range r.Hint {
		content := h.Content
		ch.Hints = append(ch.Hints, ctf.Hint{
			ID:      fmt.Sprintf("%d-%d", r.ID, i+1),
			Title:   "released " + time.Unix(int64(h.PublicTime), 0).UTC().Format(time.RFC3339),
			Content: &content,
		})
	}
	return ch
}

func (d *Driver) raw(ctx context.Context) ([]rawChallenge, error) {
	var list []rawChallenge
	if err := d.getJSON(ctx, "/dashboard/challenge_data", &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	list, err := d.raw(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ctf.Challenge, 0, len(list))
	for _, r := range list {
		out = append(out, d.toChallenge(r))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i].ID)
		b, _ := strconv.Atoi(out[j].ID)
		return a < b
	})
	return out, nil
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	id = strings.TrimSpace(id)
	list, err := d.raw(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		if strconv.Itoa(r.ID) == id {
			ch := d.toChallenge(r)
			return &ch, nil
		}
	}
	return nil, ctf.Errorf(ctf.KindNotFound, "HITCON challenge %q not found (or not released yet)", id)
}

func (d *Driver) Hints(ctx context.Context, id string) ([]ctf.Hint, error) {
	ch, err := d.GetChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	if ch.Hints == nil {
		return []ctf.Hint{}, nil
	}
	return ch.Hints, nil
}

// PrepareDownload: attachments are public object-storage links; files on the
// scoreboard origin itself need the session cookie.
func (d *Driver) PrepareDownload(_ context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	link := fileURL
	if strings.HasPrefix(link, "/") {
		link = d.base + link
	}
	dr := &ctf.DownloadRequest{URL: link}
	if core.SameOrigin(link, d.base) && d.session != "" {
		dr.Headers = map[string]string{"Cookie": "sessionid=" + d.session}
	}
	return dr, nil
}

// --- submit ------------------------------------------------------------------

var csrfInputRe = regexp.MustCompile(`name="csrfmiddlewaretoken"\s+value="([^"]+)"`)

// csrfToken returns a token for X-CSRFToken. Django accepts either the raw
// csrftoken cookie or the masked form token; without a configured cookie the
// dashboard page supplies both (and sets the cookie in the jar).
func (d *Driver) csrfToken(ctx context.Context) (string, error) {
	if err := d.seed(); err != nil {
		return "", err
	}
	page, err := d.getHTML(ctx, "/dashboard/")
	if err != nil {
		return "", err
	}
	for _, c := range d.site.Jar.Cookies(d.baseURL) {
		if c.Name == "csrftoken" && c.Value != "" {
			return c.Value, nil
		}
	}
	if m := csrfInputRe.FindStringSubmatch(page); m != nil {
		return m[1], nil
	}
	return "", ctf.Errorf(ctf.KindRemote, "HITCON: no CSRF token found on /dashboard/; set HITCON_CSRFTOKEN to the browser's csrftoken cookie")
}

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	n, err := strconv.Atoi(strings.TrimSpace(id))
	if err != nil || n <= 0 {
		return nil, ctf.Errorf(ctf.KindUsage, "HITCON challenge ID must be a positive integer, got %q", id)
	}
	tok, err := d.csrfToken(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{"flag": {strings.TrimSpace(flag)}, "id": {strconv.Itoa(n)}}
	resp, err := d.do(ctx, http.MethodPost, "/dashboard/submit_flag", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
		"X-CSRFToken":  tok,
		"Origin":       d.base,
		"Referer":      d.base + "/dashboard/",
	}, form.Encode())
	if err != nil {
		return nil, err
	}
	return classifySubmit(strconv.Itoa(n), resp)
}

func classifySubmit(id string, resp *core.Response) (*ctf.SubmitResult, error) {
	res := &ctf.SubmitResult{ChallengeID: id, HTTPStatus: resp.Status}
	var body struct {
		Result string `json:"result"`
		Detail string `json:"detail"`
	}
	isJSON := resp.JSON(&body)
	if resp.Status >= 300 {
		if !isJSON {
			if resp.Status == 403 && strings.Contains(string(resp.Body), "CSRF") {
				return nil, ctf.Errorf(ctf.KindAuth, "HITCON rejected the CSRF token; set HITCON_CSRFTOKEN to the browser's csrftoken cookie")
			}
			return nil, core.StatusError(resp.Status, "HITCON submit", core.Truncate(string(resp.Body), 160))
		}
		res.Message, res.ResponseKind = body.Detail, "detail"
		m := strings.ToLower(body.Detail)
		switch {
		case resp.Status == 429:
			res.Status = ctf.StatusRateLimited
		case strings.Contains(m, "not start") || strings.Contains(m, "not begun") || strings.Contains(m, "yet"):
			res.Status = ctf.StatusNotStarted
		case strings.Contains(m, "end") || strings.Contains(m, "over") || strings.Contains(m, "closed"):
			res.Status = ctf.StatusEnded
		case resp.Status == 404 || strings.Contains(m, "challenge"):
			res.Status = ctf.StatusBadChallenge
		case resp.Status == 403:
			res.Status = ctf.StatusNotStarted // per dashboard.js: 403 = contest not running
		default:
			res.Status = ctf.StatusError
		}
		return res, nil
	}
	if !isJSON || body.Result == "" {
		return nil, ctf.Errorf(ctf.KindRemote, "HITCON submit: unexpected response %q", core.Truncate(string(resp.Body), 160))
	}
	res.ResponseKind = body.Result
	switch body.Result {
	case "wrong":
		res.Status, res.Message = ctf.StatusIncorrect, "Wrong flag."
	case "duplicated":
		res.Status, res.Message = ctf.StatusAlreadySolved, "You already submitted this flag."
	default: // the dashboard treats every other 2xx result as a solve
		res.Status, res.Correct, res.Message = ctf.StatusCorrect, true, "Correct flag."
	}
	return res, nil
}

// --- solves, scoreboard, team ------------------------------------------------

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	list, err := d.raw(ctx)
	if err != nil {
		return nil, err
	}
	out := []ctf.Solve{}
	for _, r := range list {
		if r.Solved {
			pts := r.Score
			out = append(out, ctf.Solve{ChallengeID: strconv.Itoa(r.ID), Name: r.Name, Category: r.Category, Points: &pts})
		}
	}
	return out, nil
}

type teamStat struct {
	ID             int     `json:"id"`
	Name           string  `json:"name"`
	Score          float64 `json:"score"`
	Country        string  `json:"country_name"`
	LastSubmit     float64 `json:"last_submit_time"`
	SolvedChallIDs []int   `json:"solved_challenge"`
}

func (d *Driver) scoreboard(ctx context.Context) ([]teamStat, error) {
	var sb struct {
		Teamstat []teamStat `json:"teamstat"`
	}
	if err := d.getJSON(ctx, "/dashboard/scoreboard_data", &sb); err != nil {
		return nil, err
	}
	return sb.Teamstat, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	teams, err := d.scoreboard(ctx)
	if err != nil {
		return nil, err
	}
	sb := &ctf.Scoreboard{Total: len(teams), Entries: []ctf.ScoreEntry{}}
	for i, t := range teams {
		if i < q.Offset {
			continue
		}
		if q.Limit > 0 && len(sb.Entries) >= q.Limit {
			break
		}
		sb.Entries = append(sb.Entries, ctf.ScoreEntry{
			Position: i + 1, AccountID: strconv.Itoa(t.ID), AccountType: "team", Name: t.Name, Score: t.Score,
			Extra: map[string]any{"country": t.Country, "solved": len(t.SolvedChallIDs)},
		})
	}
	return sb, nil
}

var (
	teamIDRe   = regexp.MustCompile(`teamId:\s*(-?\d+)`)
	teamNameRe = regexp.MustCompile(`(?s)<div class="col-lg-8[^"]*">\s*<h4>(.*?)</h4>`)
	rowRe      = regexp.MustCompile(`(?s)<div class="col-lg-2">\s*([A-Za-z ]+):\s*</div>\s*<div class="col-lg-10">(.*?)</div>`)
	tagRe      = regexp.MustCompile(`<[^>]+>`)
)

func stripTags(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRe.ReplaceAllString(s, " "))), " ")
}

// Team reads /team/. The team token on that page is deliberately not returned.
func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	page, err := d.getHTML(ctx, "/team/")
	if err != nil {
		return nil, err
	}
	team := &ctf.Account{Extra: map[string]any{}}
	if m := teamIDRe.FindStringSubmatch(page); m != nil {
		team.ID = m[1]
	}
	if m := teamNameRe.FindStringSubmatch(page); m != nil {
		team.Name = stripTags(m[1])
	}
	for _, m := range rowRe.FindAllStringSubmatch(page, -1) {
		key, val := strings.ToLower(strings.TrimSpace(m[1])), stripTags(m[2])
		switch key {
		case "score":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				team.Score = &f
			}
		case "rank":
			pos, total, _ := strings.Cut(val, "/")
			if p, err := strconv.Atoi(strings.TrimSpace(pos)); err == nil {
				team.Place = &p
			}
			if t, err := strconv.Atoi(strings.TrimSpace(total)); err == nil {
				team.Extra["teams"] = t
			}
		case "country":
			team.Extra["country"] = val
		}
	}
	if team.Name == "" && team.ID == "" {
		return nil, ctf.Errorf(ctf.KindRemote, "HITCON /team/ did not look like a team page")
	}
	return &ctf.TeamStatus{Team: team}, nil
}
