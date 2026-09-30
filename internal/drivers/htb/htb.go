// Package htb implements the Hack The Box CTF driver (ctf.hackthebox.com).
// Authentication is a JWT bearer token; one profile targets one event.
//
// API reference: ctfbridge (MIT) ctfbridge/platforms/htb/**. Endpoints and
// JSON field names below were read from that client; where a route is
// ambiguous it is flagged inline.
package htb

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// defaultBase is the only public HTB CTF host.
const defaultBase = "https://ctf.hackthebox.com"

// HTB API routes. All are under /api.
const (
	// challengeListPath is the event detail + challenge list route. The live
	// HTB UI uses the SINGULAR /api/ctf/<id>; ctfbridge instead uses the plural
	// /api/ctfs/<id> and admits its per-challenge detail route is copied from
	// GZCTF (and therefore wrong). We default to the singular form; the
	// /api/ctf vs /api/ctfs choice must be confirmed against a live event.
	challengeListPath = "/api/ctf/"
	categoriesPath    = "/api/public/challenge-categories" // -> [{id,name}]
	submitPath        = "/api/flags/own"                   // POST {challenge_id,flag}
	scoresPath        = "/api/ctfs/scores/"                // plural, confirmed in ctfbridge
	downloadPath      = "/api/challenges/"                 // + <id>/download
)

// eventPathRe pulls the numeric event id out of an HTB URL. The live UI path is
// /event/<id>; /ctf(s)/<id> are accepted defensively.
var eventPathRe = regexp.MustCompile(`/(?:ctf|ctfs|event)/(\d+)`)

var Spec = driver.Spec{
	Name:        "htb",
	DisplayName: "HTB CTF",
	Description: "Hack The Box CTF (ctf.hackthebox.com) with a JWT bearer token; one event per profile",
	Kind:        "builtin",
	Example: `# HTB CTF profile for ctfx
CTFX_PLATFORM="htb"
# Site root or an event URL (https://ctf.hackthebox.com/event/1 sets the event ID).
HTB_URL="https://ctf.hackthebox.com"
HTB_EVENT=""            # CTF/event id; overrides the one derived from HTB_URL
HTB_TOKEN=""            # JWT bearer token copied from your browser session
HTB_VERIFY_SSL="true"
`,
	New:    New,
	Detect: Detect,
}

// Driver talks to one event on ctf.hackthebox.com.
type Driver struct {
	ctf.Unsupported
	client *http.Client
	base   string
	event  string
	token  string

	catsOnce sync.Once
	cats     map[string]string
}

// splitURL separates an HTB URL into its site base and an optional event id.
func splitURL(raw string) (base, event string, err error) {
	base, err = core.NormalizeBaseURL(raw)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(base)
	if m := eventPathRe.FindStringSubmatch(u.Path); m != nil {
		event = m[1]
		u.Path, u.RawPath = "", ""
		base = strings.TrimRight(u.String(), "/")
	}
	return base, event, nil
}

// New builds an HTB driver. Token and event are validated lazily, per
// operation, so config-error messages can name the exact missing key.
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	rawURL := c.Get("URL")
	token := c.Get("TOKEN")
	if rawURL == "" && token == "" {
		return nil, ctf.Errorf(ctf.KindConfig,
			"HTB requires HTB_TOKEN (JWT) and HTB_EVENT; set them in %s or the environment", c.Source)
	}
	base, event := defaultBase, ""
	if rawURL != "" {
		b, ev, err := splitURL(rawURL)
		if err != nil {
			return nil, ctf.Errorf(ctf.KindConfig, "HTB_URL is invalid; set it in %s or the environment", c.Source)
		}
		base, event = b, ev
	}
	if ev := c.Get("EVENT"); ev != "" {
		event = ev
	}
	return &Driver{client: env.Client, base: base, event: event, token: token}, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	// Team is intentionally omitted: HTB exposes no verified authenticated
	// team-status endpoint via this client, so it is left unsupported rather
	// than faked. Hints/instances are not part of HTB CTF.
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Download: true}
}

func (d *Driver) requireToken() error {
	if d.token == "" {
		return ctf.Errorf(ctf.KindConfig, "HTB authentication required: set HTB_TOKEN to your JWT")
	}
	return nil
}

func (d *Driver) requireEvent() error {
	if strings.TrimSpace(d.event) == "" {
		return ctf.Errorf(ctf.KindConfig, "HTB event ID is unknown: set HTB_EVENT or use an event URL like %s/event/1", d.base)
	}
	return nil
}

// raw performs one bearer-authenticated request against the HTB API.
func (d *Driver) raw(ctx context.Context, method, path string, body any) (*core.Response, error) {
	u, err := core.JoinURL(d.base, path)
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Accept": "application/json"}
	if d.token != "" {
		h["Authorization"] = "Bearer " + d.token
	}
	return core.Do(ctx, d.client, core.Request{Method: method, URL: u, Headers: h, JSON: body})
}

// Wire types (snake_case JSON, per ctfbridge's HTB models).

type htbChallenge struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	Points     float64 `json:"points"`
	CategoryID int     `json:"challenge_category_id"`
	Descr      string  `json:"description"`
	Content    string  `json:"content"` // full body; present in detail, may be empty in the list
	Creator    string  `json:"creator"`
	Filename   string  `json:"filename"`
	Solved     bool    `json:"solved"`
	Solves     *int    `json:"solves"` // solve count: inferred, not confirmed in ctfbridge
}

type eventPayload struct {
	Challenges []htbChallenge `json:"challenges"`
}

// categories fetches the id->name map once. It is best-effort: any failure
// yields an empty map so callers fall back to the raw category id.
func (d *Driver) categories(ctx context.Context) map[string]string {
	d.catsOnce.Do(func() {
		d.cats = map[string]string{}
		resp, err := d.raw(ctx, http.MethodGet, categoriesPath, nil)
		if err != nil || resp.Status >= 400 {
			return
		}
		var list []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}
		if resp.JSON(&list) {
			for _, c := range list {
				d.cats[strconv.Itoa(c.ID)] = c.Name
			}
		}
	})
	return d.cats
}

// fetchEvent fetches the event payload and the category map.
func (d *Driver) fetchEvent(ctx context.Context) (*eventPayload, map[string]string, error) {
	if err := d.requireToken(); err != nil {
		return nil, nil, err
	}
	if err := d.requireEvent(); err != nil {
		return nil, nil, err
	}
	resp, err := d.raw(ctx, http.MethodGet, challengeListPath+d.event, nil)
	if err != nil {
		return nil, nil, err
	}
	if resp.Status == 401 || resp.Status == 403 {
		return nil, nil, ctf.Errorf(ctf.KindAuth, "HTB authentication failed (HTTP %d): check HTB_TOKEN", resp.Status)
	}
	if resp.Status >= 400 {
		return nil, nil, core.StatusError(resp.Status, "HTB event "+d.event, core.Truncate(string(resp.Body), 200))
	}
	var ev eventPayload
	if !resp.JSON(&ev) {
		return nil, nil, ctf.Errorf(ctf.KindRemote, "HTB event %s returned unexpected data: %s", d.event, core.Truncate(string(resp.Body), 200))
	}
	return &ev, d.categories(ctx), nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (d *Driver) category(c htbChallenge, cats map[string]string) string {
	if name := cats[strconv.Itoa(c.CategoryID)]; name != "" {
		return name
	}
	return strconv.Itoa(c.CategoryID)
}

func (d *Driver) mapChallenge(c htbChallenge, cats map[string]string) ctf.Challenge {
	pts := c.Points
	ch := ctf.Challenge{
		ID:          strconv.Itoa(c.ID),
		Name:        c.Name,
		Category:    d.category(c, cats),
		Author:      c.Creator,
		Points:      &pts,
		Solved:      c.Solved,
		Solves:      c.Solves,
		Description: firstNonEmpty(c.Content, c.Descr),
	}
	if c.Filename != "" {
		if u, err := core.JoinURL(d.base, downloadPath+strconv.Itoa(c.ID)+"/download"); err == nil {
			ch.Files = []ctf.File{{Name: core.SanitizeFilename(c.Filename), URL: u}}
		}
	}
	return ch
}

func sortChallenges(out []ctf.Challenge) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if core.Deref(a.Points) != core.Deref(b.Points) {
			return core.Deref(a.Points) < core.Deref(b.Points)
		}
		return a.Name < b.Name
	})
}

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	ev, cats, err := d.fetchEvent(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ctf.Challenge, 0, len(ev.Challenges))
	for _, c := range ev.Challenges {
		ch := d.mapChallenge(c, cats)
		ch.Description, ch.Files = "", nil // keep the listing lean; details come from GetChallenge
		out = append(out, ch)
	}
	sortChallenges(out)
	return out, nil
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	id = strings.TrimSpace(id)
	ev, cats, err := d.fetchEvent(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range ev.Challenges {
		if strconv.Itoa(c.ID) == id {
			ch := d.mapChallenge(c, cats)
			return &ch, nil
		}
	}
	return nil, ctf.Errorf(ctf.KindNotFound, "HTB challenge not found: %s", id)
}

// Submit posts a flag. A wrong flag is a result, not an error; only auth,
// transport, and malformed-input failures return an error.
func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	if err := d.requireToken(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	cid, err := strconv.Atoi(id)
	if err != nil || cid <= 0 {
		return nil, ctf.Errorf(ctf.KindUsage, "HTB challenge IDs are positive integers, got %q", id)
	}
	resp, err := d.raw(ctx, http.MethodPost, submitPath, map[string]any{"challenge_id": cid, "flag": flag})
	if err != nil {
		return nil, err
	}
	var body struct {
		Message string `json:"message"`
	}
	resp.JSON(&body)
	res := &ctf.SubmitResult{ChallengeID: id, HTTPStatus: resp.Status, Message: body.Message,
		ResponseKind: "HTTP " + strconv.Itoa(resp.Status)}
	switch {
	case resp.Status == 401 || resp.Status == 403:
		return nil, ctf.Errorf(ctf.KindAuth, "HTB submit denied (HTTP %d): %s", resp.Status,
			firstNonEmpty(body.Message, "check HTB_TOKEN"))
	case resp.Status == 200:
		res.Status, res.Correct = ctf.StatusCorrect, true
	case resp.Status == 429:
		res.Status = ctf.StatusRateLimited
	case resp.Status == 404 || resp.Status == 302: // ctfbridge treats a 302 as challenge-not-found
		res.Status = ctf.StatusBadChallenge
	case resp.Status == 400:
		if strings.Contains(strings.ToLower(body.Message), "already") {
			res.Status = ctf.StatusAlreadySolved
		} else {
			res.Status = ctf.StatusIncorrect
		}
	default:
		res.Status = ctf.StatusError
	}
	return res, nil
}

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	ev, cats, err := d.fetchEvent(ctx)
	if err != nil {
		return nil, err
	}
	out := []ctf.Solve{}
	for _, c := range ev.Challenges {
		if !c.Solved {
			continue
		}
		pts := c.Points
		out = append(out, ctf.Solve{ChallengeID: strconv.Itoa(c.ID), Name: c.Name,
			Category: d.category(c, cats), Points: &pts})
	}
	return out, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	if err := d.requireToken(); err != nil {
		return nil, err
	}
	if err := d.requireEvent(); err != nil {
		return nil, err
	}
	resp, err := d.raw(ctx, http.MethodGet, scoresPath+d.event, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 || resp.Status == 403 {
		return nil, ctf.Errorf(ctf.KindAuth, "HTB authentication failed (HTTP %d): check HTB_TOKEN", resp.Status)
	}
	if resp.Status >= 400 {
		return nil, core.StatusError(resp.Status, "HTB scoreboard", core.Truncate(string(resp.Body), 200))
	}
	var sb struct {
		Total  *int `json:"total"` // reported total: inferred, not confirmed
		Scores []struct {
			ID          int     `json:"id"`
			Name        string  `json:"name"`
			Points      float64 `json:"points"`
			OwnedFlags  int     `json:"owned_flags"`
			CountryCode string  `json:"country_code"`
		} `json:"scores"`
	}
	if !resp.JSON(&sb) {
		return nil, ctf.Errorf(ctf.KindRemote, "HTB scoreboard returned unexpected data: %s", core.Truncate(string(resp.Body), 200))
	}
	out := &ctf.Scoreboard{Total: len(sb.Scores), Entries: []ctf.ScoreEntry{}}
	if sb.Total != nil {
		out.Total = *sb.Total
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	for i := q.Offset; i >= 0 && i < len(sb.Scores) && i < q.Offset+limit; i++ {
		e := sb.Scores[i]
		out.Entries = append(out.Entries, ctf.ScoreEntry{
			Position: i + 1, AccountID: strconv.Itoa(e.ID), AccountType: "team",
			Name: e.Name, Score: e.Points,
			Extra: map[string]any{"owned_flags": e.OwnedFlags, "country_code": e.CountryCode},
		})
	}
	return out, nil
}

func (d *Driver) PrepareDownload(ctx context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	u, err := core.JoinURL(d.base, fileURL)
	if err != nil {
		return nil, err
	}
	dr := &ctf.DownloadRequest{URL: u}
	if core.SameOrigin(u, d.base) && d.token != "" {
		dr.Headers = map[string]string{"Authorization": "Bearer " + d.token}
	}
	return dr, nil
}

// Detect recognizes HTB purely by host; the platform is a single known site,
// so no network probe is needed. An /event|ctf(s)/<id> path fills HTB_EVENT.
func Detect(ctx context.Context, c *http.Client, rawURL string) (*driver.Detection, bool) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + strings.TrimSpace(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Host, "ctf.hackthebox.com") {
		return nil, false
	}
	det := &driver.Detection{BaseURL: defaultBase}
	if m := eventPathRe.FindStringSubmatch(u.Path); m != nil {
		det.Values = map[string]string{"HTB_EVENT": m[1]}
	}
	return det, true
}
