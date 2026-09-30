// Package gzctf implements the GZCTF driver (GZCTF_Token cookie or
// username/password login). One profile targets one game.
//
// API reference: GZTimeWalker/GZCTF src/GZCTF/Controllers/{Game,Account,Info}Controller.cs.
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
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

var Spec = driver.Spec{
	Name:        "gzctf",
	DisplayName: "GZCTF",
	Description: "GZCTF with GZCTF_Token cookie or username/password; hints and container instances",
	Kind:        "builtin",
	Example: `# GZCTF profile for ctfx
CTFX_PLATFORM="gzctf"
# Site root or a game URL (https://host/games/12 sets the game ID).
GZCTF_URL="https://your-gzctf-instance.example"
# GZCTF_GAME="12"          # game ID; overrides the one derived from GZCTF_URL
GZCTF_VERIFY_SSL="true"
# The scoreboard works without auth. Everything else needs one of:
# GZCTF_TOKEN=""           # browser cookie value of GZCTF_Token
# GZCTF_USERNAME=""        # username or email, with GZCTF_PASSWORD
# GZCTF_PASSWORD=""
`,
	New:    New,
	Detect: Detect,
}

// cookieName is the ASP.NET Identity application cookie GZCTF configures.
const cookieName = "GZCTF_Token"

// GZCTF error codes carried in RequestResponse.status (Utils/Enums.cs ErrorCodes).
const (
	codeGameNotStarted = 10001
	codeGameEnded      = 10002
)

var gamePathRe = regexp.MustCompile(`^(.*?)/games/(\d+)(?:/.*)?$`)

// Driver talks to one game on one GZCTF instance.
type Driver struct {
	ctf.Unsupported
	client   *http.Client
	base     string
	game     string
	cookie   string // full Cookie header value once authenticated
	username string
	password string

	// pollDelay and pollTimeout bound flag-judging polling.
	pollDelay   time.Duration
	pollTimeout time.Duration

	once    sync.Once
	authErr error

	keyOnce sync.Once
	pubKey  string
}

// splitURL separates a GZCTF URL into its site base and an optional game ID.
func splitURL(raw string) (base, game string, err error) {
	base, err = core.NormalizeBaseURL(raw)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(base)
	if m := gamePathRe.FindStringSubmatch(u.Path); m != nil {
		u.Path, u.RawPath = m[1], ""
		return strings.TrimRight(u.String(), "/"), m[2], nil
	}
	return base, "", nil
}

// New builds a GZCTF driver.
func New(env *driver.Env) (ctf.Driver, error) {
	c := env.Config
	base, game, err := splitURL(c.Get("URL"))
	if err != nil {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF_URL is missing or invalid; set it in %s or the environment", c.Source)
	}
	if g := c.Get("GAME"); g != "" {
		game = g
	}
	if game == "" {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF game ID is unknown: set GZCTF_GAME or use a game URL like %s/games/1", base)
	}
	if n, err := strconv.Atoi(game); err != nil || n <= 0 {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF_GAME must be a positive integer, got %q", game)
	}
	d := &Driver{client: env.Client, base: base, game: game,
		username: c.Get("USERNAME"), password: c.Get("PASSWORD"),
		pollDelay: 500 * time.Millisecond, pollTimeout: 20 * time.Second}
	tok := strings.TrimPrefix(c.Get("TOKEN"), cookieName+"=")
	if tok != "" && d.username != "" {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF config is ambiguous: set GZCTF_TOKEN or GZCTF_USERNAME/GZCTF_PASSWORD, not both")
	}
	if (d.username == "") != (d.password == "") {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF login needs both GZCTF_USERNAME and GZCTF_PASSWORD")
	}
	if tok != "" {
		d.cookie = cookieName + "=" + tok
	}
	return d, nil
}

func (d *Driver) Capabilities() ctf.Capabilities {
	return ctf.Capabilities{Challenges: true, Submit: true, Solves: true, Scoreboard: true, Team: true,
		Download: true, Hints: true, Instances: true}
}

// reqResponse is GZCTF's RequestResponse error body.
type reqResponse struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
}

func errBody(resp *core.Response) reqResponse {
	var r reqResponse
	if !resp.JSON(&r) || r.Title == "" {
		r.Title = core.Truncate(string(resp.Body), 200)
	}
	return r
}

func (d *Driver) gamePath(parts ...string) string {
	return "Game/" + d.game + "/" + strings.Join(parts, "/")
}

func (d *Driver) raw(ctx context.Context, method, path string, body any) (*core.Response, error) {
	u, err := core.JoinURL(d.base+"/api/", path)
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Accept": "application/json"}
	if d.cookie != "" {
		h["Cookie"] = d.cookie
	}
	return core.Do(ctx, d.client, core.Request{Method: method, URL: u, Headers: h, JSON: body})
}

// publicKey returns the API encryption public key, or "" when the instance
// does not encrypt flags and passwords.
func (d *Driver) publicKey(ctx context.Context) string {
	d.keyOnce.Do(func() {
		resp, err := d.raw(ctx, http.MethodGet, "Config", nil)
		if err != nil || resp.Status >= 400 {
			return
		}
		var cfg struct {
			APIPublicKey string `json:"apiPublicKey"`
		}
		if resp.JSON(&cfg) {
			d.pubKey = cfg.APIPublicKey
		}
	})
	return d.pubKey
}

// seal encrypts s the way GZCTF's CryptoUtils.DecryptData expects:
// base64(ephemeral X25519 pub || 12-byte nonce || AES-256-GCM(sha256(shared)) ciphertext+tag).
func seal(pubB64, s string) (string, error) {
	pk, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "", ctf.Errorf(ctf.KindRemote, "GZCTF API public key is not base64: %v", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pk)
	if err != nil {
		return "", ctf.Errorf(ctf.KindRemote, "GZCTF API public key is invalid: %v", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256(shared)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	out := append([]byte{}, eph.PublicKey().Bytes()...)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, []byte(s), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// apiData encrypts s when the instance has API encryption enabled.
func (d *Driver) apiData(ctx context.Context, s string) (string, error) {
	if pk := d.publicKey(ctx); pk != "" {
		return seal(pk, s)
	}
	return s, nil
}

// authenticate logs in once when username/password are configured.
func (d *Driver) authenticate(ctx context.Context) error {
	d.once.Do(func() {
		if d.cookie != "" || d.username == "" {
			return
		}
		pw, err := d.apiData(ctx, d.password)
		if err != nil {
			d.authErr = err
			return
		}
		resp, err := d.raw(ctx, http.MethodPost, "Account/LogIn", map[string]any{"userName": d.username, "password": pw})
		if err != nil {
			d.authErr = err
			return
		}
		if resp.Status >= 400 {
			d.authErr = ctf.Errorf(ctf.KindAuth, "GZCTF login as %s failed (HTTP %d): %s", d.username, resp.Status, errBody(resp).Title)
			return
		}
		// ASP.NET may chunk a large auth cookie into GZCTF_Token, GZCTF_TokenC1, ...
		var parts []string
		for _, ck := range (&http.Response{Header: resp.Header}).Cookies() {
			if strings.HasPrefix(ck.Name, cookieName) && ck.Value != "" {
				parts = append(parts, ck.Name+"="+ck.Value)
			}
		}
		if len(parts) == 0 {
			d.authErr = ctf.Errorf(ctf.KindAuth, "GZCTF login as %s returned no %s cookie (captcha enabled? use GZCTF_TOKEN instead)", d.username, cookieName)
			return
		}
		d.cookie = strings.Join(parts, "; ")
	})
	return d.authErr
}

func (d *Driver) authHint() string {
	if d.username != "" {
		return "check GZCTF_USERNAME/GZCTF_PASSWORD"
	}
	return "check GZCTF_TOKEN (it may have expired)"
}

// call performs an authenticated (unless public) request and maps auth failures.
func (d *Driver) call(ctx context.Context, method, path string, body any, public bool) (*core.Response, error) {
	if err := d.authenticate(ctx); err != nil {
		return nil, err
	}
	if d.cookie == "" && !public {
		return nil, ctf.Errorf(ctf.KindConfig, "GZCTF authentication required: set GZCTF_TOKEN or GZCTF_USERNAME/GZCTF_PASSWORD")
	}
	resp, err := d.raw(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if resp.Status == 401 {
		return nil, ctf.Errorf(ctf.KindAuth, "GZCTF authentication failed (%s): %s", errBody(resp).Title, d.authHint())
	}
	return resp, nil
}

// api performs call and decodes a 2xx JSON body into out.
func (d *Driver) api(ctx context.Context, method, path string, body any, public bool, out any) error {
	resp, err := d.call(ctx, method, path, body, public)
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		e := errBody(resp)
		switch e.Status {
		case codeGameNotStarted:
			return ctf.Errorf(ctf.KindRemote, "GZCTF game %s has not started: %s", d.game, e.Title)
		case codeGameEnded:
			return ctf.Errorf(ctf.KindRemote, "GZCTF game %s has ended: %s", d.game, e.Title)
		}
		return core.StatusError(resp.Status, "GZCTF "+path, e.Title)
	}
	if out != nil && !resp.JSON(out) {
		return ctf.Errorf(ctf.KindRemote, "GZCTF %s returned unexpected data: %s", path, core.Truncate(string(resp.Body), 200))
	}
	return nil
}

// Wire types (camelCase JSON from ASP.NET).

type challengeInfo struct {
	ID       int     `json:"id"`
	Title    string  `json:"title"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Solved   int     `json:"solved"`
	Deadline string  `json:"deadline"`
}

type solvedItem struct {
	ID       int     `json:"id"`
	Score    float64 `json:"score"`
	Type     string  `json:"type"`
	UserName string  `json:"userName"`
	Time     string  `json:"time"`
}

type boardItem struct {
	ID               int          `json:"id"`
	Name             string       `json:"name"`
	Bio              string       `json:"bio"`
	DivisionID       *int         `json:"divisionId"`
	Score            float64      `json:"score"`
	Rank             int          `json:"rank"`
	DivisionRank     *int         `json:"divisionRank"`
	SolvedChallenges []solvedItem `json:"solvedChallenges"`
}

type gameDetail struct {
	Challenges map[string][]challengeInfo `json:"challenges"`
	Rank       *boardItem                 `json:"rank"`
}

type challengeDetail struct {
	ID       int      `json:"id"`
	Title    string   `json:"title"`
	Content  string   `json:"content"`
	Category string   `json:"category"`
	Hints    []string `json:"hints"`
	Score    float64  `json:"score"`
	Type     string   `json:"type"`
	Limit    int      `json:"limit"`
	Attempts int      `json:"attempts"`
	Deadline *string  `json:"deadline"`
	Context  struct {
		CloseTime     *string `json:"closeTime"`
		InstanceEntry *string `json:"instanceEntry"`
		URL           *string `json:"url"`
		FileSize      *int64  `json:"fileSize"`
	} `json:"context"`
}

type containerInfo struct {
	Status       string `json:"status"`
	StartedAt    string `json:"startedAt"`
	ExpectStopAt string `json:"expectStopAt"`
	Entry        string `json:"entry"`
}

func (d *Driver) details(ctx context.Context) (*gameDetail, error) {
	var g gameDetail
	if err := d.api(ctx, http.MethodGet, d.gamePath("Details"), nil, false, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *gameDetail) solved() map[int]solvedItem {
	m := map[int]solvedItem{}
	if g.Rank != nil {
		for _, s := range g.Rank.SolvedChallenges {
			m[s.ID] = s
		}
	}
	return m
}

func (g *gameDetail) all() []challengeInfo {
	var out []challengeInfo
	for cat, cs := range g.Challenges {
		for _, c := range cs {
			if c.Category == "" {
				c.Category = cat
			}
			out = append(out, c)
		}
	}
	return out
}

func f64(v float64) *float64 { return &v }
func intp(v int) *int        { return &v }

func (d *Driver) ListChallenges(ctx context.Context) ([]ctf.Challenge, error) {
	g, err := d.details(ctx)
	if err != nil {
		return nil, err
	}
	solved := g.solved()
	out := []ctf.Challenge{}
	for _, c := range g.all() {
		ch := ctf.Challenge{ID: strconv.Itoa(c.ID), Name: c.Title, Category: c.Category,
			Points: f64(c.Score), Solves: intp(c.Solved)}
		_, ch.Solved = solved[c.ID]
		if c.Deadline != "" {
			ch.Extra = map[string]any{"deadline": c.Deadline}
		}
		out = append(out, ch)
	}
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
	return out, nil
}

// challengeID validates a numeric GZCTF challenge ID. Non-numeric input is a
// usage error so the CLI can retry after resolving a challenge name.
func challengeID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if n, err := strconv.Atoi(id); err != nil || n <= 0 {
		return "", ctf.Errorf(ctf.KindUsage, "GZCTF challenge IDs are positive integers, got %q", id)
	}
	return id, nil
}

func isContainer(typ string) bool { return strings.Contains(typ, "Container") }

func (d *Driver) challengeDetail(ctx context.Context, id string) (*challengeDetail, error) {
	var c challengeDetail
	if err := d.api(ctx, http.MethodGet, d.gamePath("Challenges", id), nil, false, &c); err != nil {
		if ctf.KindOf(err) == ctf.KindNotFound {
			return nil, ctf.Errorf(ctf.KindNotFound, "GZCTF challenge not found: %s", id)
		}
		return nil, err
	}
	return &c, nil
}

func (d *Driver) GetChallenge(ctx context.Context, id string) (*ctf.Challenge, error) {
	id, err := challengeID(id)
	if err != nil {
		return nil, err
	}
	c, err := d.challengeDetail(ctx, id)
	if err != nil {
		return nil, err
	}
	ch := &ctf.Challenge{ID: strconv.Itoa(c.ID), Name: c.Title, Category: c.Category, Points: f64(c.Score),
		Description: c.Content, Hints: mapHints(c.Hints)}
	ch.Extra = map[string]any{"type": c.Type, "attempts": c.Attempts}
	if c.Limit > 0 {
		ch.Extra["submission_limit"] = c.Limit
	}
	if c.Deadline != nil {
		ch.Extra["deadline"] = *c.Deadline
	}
	if u := deref(c.Context.URL); u != "" {
		if full, err := core.JoinURL(d.base, u); err == nil {
			ch.Files = []ctf.File{{Name: core.FilenameFromURL(full), URL: full}}
			if c.Context.FileSize != nil {
				ch.Extra["file_size"] = *c.Context.FileSize
			}
		}
	}
	if isContainer(c.Type) {
		ch.Instance = &ctf.InstanceRef{Backend: "gzctf", Slug: ch.ID}
		if e := deref(c.Context.InstanceEntry); e != "" {
			cn := d.connect(e)
			ch.Connection = cn.Host
			if ch.Connection == "" {
				ch.Connection = cn.URL
			}
		}
		if t := deref(c.Context.CloseTime); t != "" {
			ch.Extra["instance_expires"] = t
		}
	}
	// Solve count and solved state live only in the game details; best effort.
	if g, err := d.details(ctx); err == nil {
		_, ch.Solved = g.solved()[c.ID]
		for _, info := range g.all() {
			if info.ID == c.ID {
				ch.Solves = intp(info.Solved)
			}
		}
	}
	return ch, nil
}

func mapHints(hs []string) []ctf.Hint {
	var out []ctf.Hint
	for i, h := range hs {
		h := h
		out = append(out, ctf.Hint{ID: strconv.Itoa(i + 1), Content: &h})
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (d *Driver) Hints(ctx context.Context, challengeID string) ([]ctf.Hint, error) {
	ch, err := d.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if ch.Hints == nil {
		return []ctf.Hint{}, nil
	}
	return ch.Hints, nil
}

// answerStatus maps AnswerResult (string enum; ints tolerated) to a status.
// FlagSubmitted means the judge has not run yet and is reported as "".
func answerStatus(raw []byte) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var n int
		if json.Unmarshal(raw, &n) != nil {
			return "", false
		}
		s = map[int]string{0: "FlagSubmitted", 1: "Accepted", 2: "WrongAnswer", 3: "CheatDetected", -1: "NotFound"}[n]
	}
	switch s {
	case "FlagSubmitted":
		return "", true
	case "Accepted":
		return ctf.StatusCorrect, true
	case "WrongAnswer", "CheatDetected":
		return ctf.StatusIncorrect, true
	case "NotFound":
		return ctf.StatusBadChallenge, true
	}
	return "", false
}

func (d *Driver) Submit(ctx context.Context, id, flag string) (*ctf.SubmitResult, error) {
	id, err := challengeID(id)
	if err != nil {
		return nil, err
	}
	if err := d.authenticate(ctx); err != nil {
		return nil, err
	}
	enc, err := d.apiData(ctx, flag)
	if err != nil {
		return nil, err
	}
	resp, err := d.call(ctx, http.MethodPost, d.gamePath("Challenges", id), map[string]any{"flag": enc}, false)
	if err != nil {
		return nil, err
	}
	res := &ctf.SubmitResult{ChallengeID: id, HTTPStatus: resp.Status}
	if resp.Status >= 400 {
		e := errBody(resp)
		res.Message, res.ResponseKind = e.Title, "HTTP "+strconv.Itoa(resp.Status)
		switch {
		case resp.Status == 403:
			return nil, ctf.Errorf(ctf.KindAuth, "GZCTF submit denied: %s", e.Title)
		case resp.Status == 429:
			res.Status = ctf.StatusRateLimited
		case resp.Status == 404:
			res.Status = ctf.StatusBadChallenge
		case e.Status == codeGameNotStarted:
			res.Status = ctf.StatusNotStarted
		case e.Status == codeGameEnded:
			res.Status = ctf.StatusEnded
		default:
			res.Status = ctf.StatusError
		}
		return res, nil
	}
	var subID int
	if !resp.JSON(&subID) {
		return nil, ctf.Errorf(ctf.KindRemote, "GZCTF submit returned no submission ID: %s", core.Truncate(string(resp.Body), 200))
	}
	// Judging is asynchronous: poll while the result is FlagSubmitted.
	statusPath := d.gamePath("Challenges", id, "Status", strconv.Itoa(subID))
	deadline := time.Now().Add(d.pollTimeout)
	delay := d.pollDelay
	for {
		var raw json.RawMessage
		if err := d.api(ctx, http.MethodGet, statusPath, nil, false, &raw); err != nil {
			return nil, err
		}
		st, ok := answerStatus(raw)
		if !ok {
			res.Status, res.ResponseKind, res.Message = ctf.StatusError, string(raw), "unknown GZCTF answer result "+string(raw)
			return res, nil
		}
		if st != "" {
			var kind string
			_ = json.Unmarshal(raw, &kind)
			res.Status, res.Correct, res.ResponseKind = st, st == ctf.StatusCorrect, kind
			return res, nil
		}
		if time.Now().Add(delay).After(deadline) {
			return nil, ctf.Errorf(ctf.KindRemote, "GZCTF is still judging submission %d for challenge %s after %s; check the challenge later", subID, id, d.pollTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

func (d *Driver) Solves(ctx context.Context) ([]ctf.Solve, error) {
	g, err := d.details(ctx)
	if err != nil {
		return nil, err
	}
	infos := map[int]challengeInfo{}
	for _, c := range g.all() {
		infos[c.ID] = c
	}
	out := []ctf.Solve{}
	if g.Rank == nil {
		return out, nil
	}
	for _, s := range g.Rank.SolvedChallenges {
		c := infos[s.ID]
		out = append(out, ctf.Solve{ChallengeID: strconv.Itoa(s.ID), Name: c.Title, Category: c.Category,
			Points: f64(s.Score), Date: s.Time})
	}
	return out, nil
}

func (d *Driver) Scoreboard(ctx context.Context, q ctf.ScoreboardQuery) (*ctf.Scoreboard, error) {
	var sb struct {
		Items     []boardItem `json:"items"`
		Divisions []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"divisions"`
	}
	if err := d.api(ctx, http.MethodGet, d.gamePath("Scoreboard"), nil, true, &sb); err != nil {
		return nil, err
	}
	items := sb.Items
	divName := map[int]string{}
	for _, dv := range sb.Divisions {
		divName[dv.ID] = dv.Name
	}
	if q.Division != "" {
		divID := -1
		for id, name := range divName {
			if strings.EqualFold(name, q.Division) || strconv.Itoa(id) == q.Division {
				divID = id
			}
		}
		if divID < 0 {
			return nil, ctf.Errorf(ctf.KindNotFound, "GZCTF division not found: %s", q.Division)
		}
		var f []boardItem
		for _, it := range items {
			if it.DivisionID != nil && *it.DivisionID == divID {
				f = append(f, it)
			}
		}
		items = f
	}
	rank := func(it boardItem) int {
		if q.Division != "" && it.DivisionRank != nil {
			return *it.DivisionRank
		}
		return it.Rank
	}
	sort.SliceStable(items, func(i, j int) bool { return rank(items[i]) < rank(items[j]) })
	out := &ctf.Scoreboard{Total: len(items), Entries: []ctf.ScoreEntry{}}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	for i := q.Offset; i < len(items) && i < q.Offset+limit; i++ {
		it := items[i]
		e := ctf.ScoreEntry{Position: rank(it), AccountID: strconv.Itoa(it.ID), AccountType: "team",
			Name: it.Name, Score: it.Score, Extra: map[string]any{"solved": len(it.SolvedChallenges)}}
		if e.Position <= 0 {
			e.Position = i + 1
		}
		if it.DivisionID != nil {
			e.Extra["division"] = divName[*it.DivisionID]
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

func (d *Driver) Team(ctx context.Context) (*ctf.TeamStatus, error) {
	var p struct {
		UserID   string `json:"userId"`
		UserName string `json:"userName"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := d.api(ctx, http.MethodGet, "Account/Profile", nil, false, &p); err != nil {
		return nil, err
	}
	ts := &ctf.TeamStatus{User: &ctf.Account{ID: p.UserID, Name: p.UserName, Email: p.Email,
		Extra: map[string]any{"role": p.Role}}}
	g, err := d.details(ctx)
	switch {
	case err != nil:
		ts.TeamError = err.Error()
	case g.Rank == nil:
		ts.TeamError = "no team participation in game " + d.game
	default:
		r := g.Rank
		ts.Team = &ctf.Account{ID: strconv.Itoa(r.ID), Name: r.Name, Score: f64(r.Score),
			Extra: map[string]any{"solved": len(r.SolvedChallenges), "game": d.game}}
		if r.Rank > 0 {
			ts.Team.Place = intp(r.Rank)
		}
	}
	return ts, nil
}

func (d *Driver) PrepareDownload(ctx context.Context, fileURL string) (*ctf.DownloadRequest, error) {
	u, err := core.JoinURL(d.base, fileURL)
	if err != nil {
		return nil, err
	}
	dr := &ctf.DownloadRequest{URL: u}
	if core.SameOrigin(u, d.base) {
		if err := d.authenticate(ctx); err != nil {
			return nil, err
		}
		if d.cookie != "" {
			dr.Headers = map[string]string{"Cookie": d.cookie}
		}
	}
	return dr, nil
}

// connect builds connection info from a container entry: "host:port", or a
// container GUID when the platform proxies traffic over WebSocket.
func (d *Driver) connect(entry string) *ctf.Connect {
	if host, port, ok := strings.Cut(entry, ":"); ok && !strings.Contains(port, ":") {
		return &ctf.Connect{Host: entry, Command: "nc " + host + " " + port}
	}
	ws := strings.Replace(d.base, "http", "ws", 1) + "/api/Proxy/" + url.PathEscape(entry)
	return &ctf.Connect{URL: ws, Command: "wsrx connect " + ws}
}

// Instance manages a container challenge. challenge is the numeric challenge ID.
func (d *Driver) Instance(ctx context.Context, action, challenge string) (*ctf.Instance, error) {
	id, err := challengeID(challenge)
	if err != nil {
		return nil, err
	}
	inst := &ctf.Instance{Challenge: id, Backend: "gzctf", Action: action}
	if action == ctf.InstanceStatus {
		c, err := d.challengeDetail(ctx, id)
		if err != nil {
			return nil, err
		}
		if !isContainer(c.Type) {
			return nil, ctf.Errorf(ctf.KindUnsupported, "GZCTF challenge %s (%s) has no container", id, c.Title)
		}
		inst.HTTPStatus = 200
		if e := deref(c.Context.InstanceEntry); e != "" {
			inst.Status, inst.Host, inst.Expires = "running", e, deref(c.Context.CloseTime)
			inst.Connect = d.connect(e)
		} else {
			inst.Status, inst.Message = "not_started", "instance not started"
		}
		return inst, nil
	}
	method, path := http.MethodPost, d.gamePath("Container", id)
	switch action {
	case ctf.InstanceStart:
	case ctf.InstanceExtend:
		path += "/Extend"
	case ctf.InstanceStop:
		method = http.MethodDelete
	default:
		return nil, ctf.Errorf(ctf.KindUsage, "unknown instance action %q", action)
	}
	resp, err := d.call(ctx, method, path, nil, false)
	if err != nil {
		return nil, err
	}
	inst.HTTPStatus = resp.Status
	if resp.Status >= 400 {
		inst.Status, inst.Message = "error", errBody(resp).Title
		return inst, nil
	}
	switch action {
	case ctf.InstanceStop:
		inst.Status = "terminated"
		return inst, nil
	case ctf.InstanceStart:
		inst.Status = "started"
	case ctf.InstanceExtend:
		inst.Status = "extended"
	}
	var ci containerInfo
	if !resp.JSON(&ci) {
		return nil, ctf.Errorf(ctf.KindRemote, "GZCTF %s returned unexpected data: %s", path, core.Truncate(string(resp.Body), 200))
	}
	inst.Expires = ci.ExpectStopAt
	if ci.Status != "" && ci.Status != "Running" {
		inst.Message = "container status: " + ci.Status
	}
	if ci.Entry != "" {
		inst.Host = ci.Entry
		inst.Connect = d.connect(ci.Entry)
	}
	return inst, nil
}

// Detect recognizes GZCTF from its public /api/Config (falling back to the
// site HTML) and extracts the game ID from /games/<id> URLs.
func Detect(ctx context.Context, c *http.Client, rawURL string) (*driver.Detection, bool) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + strings.TrimSpace(rawURL)
	}
	base, game, err := splitURL(rawURL)
	if err != nil {
		return nil, false
	}
	det := &driver.Detection{BaseURL: base}
	if game != "" {
		det.Values = map[string]string{"GZCTF_GAME": game}
	}
	if resp, err := core.Do(ctx, c, core.Request{URL: base + "/api/Config", Headers: map[string]string{"Accept": "application/json"}}); err == nil && resp.Status == 200 {
		var cfg map[string]any
		if resp.JSON(&cfg) {
			_, slogan := cfg["slogan"]
			_, pm := cfg["portMapping"]
			_, lt := cfg["defaultLifetime"]
			if slogan && (pm || lt) {
				return det, true
			}
		}
	}
	resp, err := core.Do(ctx, c, core.Request{URL: base + "/"})
	if err != nil || resp.Status != 200 {
		return nil, false
	}
	body := string(resp.Body)
	if strings.Contains(body, "GZCTF") || strings.Contains(body, "GZ::CTF") {
		return det, true
	}
	return nil, false
}
