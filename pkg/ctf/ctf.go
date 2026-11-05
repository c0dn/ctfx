// Package ctf defines the platform-neutral types and the Driver contract that
// every ctfx platform driver (built-in or exec plugin) implements.
package ctf

import (
	"context"
	"errors"
	"fmt"
)

// Protocol is the ctfx data contract version: the exec plugin protocol and
// the JSON shapes in this package. There is one version; older drivers are
// refused.
const Protocol = 2

// Challenge is a normalized challenge record. IDs are always strings because
// several platforms use opaque identifiers.
type Challenge struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Author      string   `json:"author,omitempty"`
	Points      *float64 `json:"points"`
	Solved      bool     `json:"solved"`
	Solves      *int     `json:"solves"`
	Description string   `json:"description,omitempty"`
	// Connection is the static target named by the challenge (not a per-team
	// instance, which is Instance's job), parsed into host, port or URL.
	Connection *Connect     `json:"connection,omitempty"`
	Files      []File       `json:"files,omitempty"`
	Hints      []Hint       `json:"hints,omitempty"`
	Instance   *InstanceRef `json:"instance,omitempty"`
	// Limits are the platform's own per-challenge limits, when it states them.
	Limits *ChallengeLimits `json:"limits,omitempty"`
	// Extra holds platform-specific fields with no shared meaning. Consumers
	// must not depend on it; anything with a shared meaning gets a real field.
	Extra map[string]any `json:"extra,omitempty"`
}

// ChallengeLimits are a challenge's platform-side limits. Nil fields are unknown.
type ChallengeLimits struct {
	// MaxAttempts is the total number of submissions allowed (0 = unlimited).
	MaxAttempts *int `json:"max_attempts,omitempty"`
	// RemainingAttempts is how many submissions are left for our team.
	RemainingAttempts *int `json:"remaining_attempts,omitempty"`
	// Deadline is when the challenge stops accepting flags (RFC 3339 UTC).
	Deadline string `json:"deadline,omitempty"`
}

// File is a downloadable challenge attachment.
type File struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Hint is a challenge hint. Content is nil while the hint is locked.
type Hint struct {
	ID      string  `json:"id"`
	Title   string  `json:"title,omitempty"`
	Cost    float64 `json:"cost"`
	Locked  bool    `json:"locked"`
	Content *string `json:"content"`
}

// InstanceRef marks a challenge that uses per-team instances.
type InstanceRef struct {
	Backend string `json:"backend"`
	Slug    string `json:"slug"`
	// Lifetime is how long a fresh instance lives, in seconds, when known.
	Lifetime int `json:"lifetime_seconds,omitempty"`
}

// Submission statuses shared across platforms.
const (
	StatusCorrect       = "correct"
	StatusIncorrect     = "incorrect"
	StatusAlreadySolved = "already_solved"
	StatusRateLimited   = "rate_limited"
	StatusBadChallenge  = "bad_challenge"
	StatusNotStarted    = "not_started"
	StatusEnded         = "ended"
	StatusError         = "error"
)

// SubmitStatuses lists every valid SubmitResult.Status.
var SubmitStatuses = []string{StatusCorrect, StatusIncorrect, StatusAlreadySolved, StatusRateLimited,
	StatusBadChallenge, StatusNotStarted, StatusEnded, StatusError}

// SubmitResult is the verdict for a flag submission. A wrong flag is not an
// error: it is a result with Status "incorrect".
type SubmitResult struct {
	ChallengeID string `json:"challenge_id"`
	// Status is one of SubmitStatuses.
	Status  string `json:"status"`
	Correct bool   `json:"correct"`
	Message string `json:"message"`
	// RetryAfter is how many seconds to wait before submitting again, set with
	// rate_limited when the platform says (Retry-After header or body).
	RetryAfter   int    `json:"retry_after_seconds,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	ResponseKind string `json:"response_kind,omitempty"`
}

// Solve is one entry of the caller's solve history.
type Solve struct {
	ChallengeID string   `json:"challenge_id,omitempty"`
	Name        string   `json:"name"`
	Category    string   `json:"category,omitempty"`
	Points      *float64 `json:"points"`
	Date        string   `json:"date,omitempty"`
}

// ScoreboardQuery selects a leaderboard slice.
type ScoreboardQuery struct {
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	Division string `json:"division,omitempty"`
}

// ScoreEntry is one leaderboard row.
type ScoreEntry struct {
	Position    int            `json:"position"`
	AccountID   string         `json:"account_id"`
	AccountType string         `json:"account_type,omitempty"`
	Name        string         `json:"name"`
	Score       float64        `json:"score"`
	Extra       map[string]any `json:"extra,omitempty"`
}

// Scoreboard is a leaderboard slice plus the platform's total, when known.
type Scoreboard struct {
	Total   int          `json:"total"`
	Entries []ScoreEntry `json:"entries"`
}

// Account describes a user or team.
type Account struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Email   string         `json:"email,omitempty"`
	Score   *float64       `json:"score"`
	Place   *int           `json:"place"`
	Members []Member       `json:"members,omitempty"`
	Extra   map[string]any `json:"extra,omitempty"`
}

// Member is a team member.
type Member struct {
	ID    string   `json:"id,omitempty"`
	Name  string   `json:"name"`
	Email string   `json:"email,omitempty"`
	Score *float64 `json:"score,omitempty"`
}

// TeamStatus is the authenticated account snapshot.
type TeamStatus struct {
	User      *Account `json:"user"`
	Team      *Account `json:"team"`
	TeamError string   `json:"team_error,omitempty"`
}

// Instance states. Every Instance.State is one of these.
const (
	// InstanceRunning: up and reachable at Connect.
	InstanceRunning = "running"
	// InstancePending: being created, reset or stopped; poll status again.
	InstancePending = "pending"
	// InstanceStopped: no instance exists for the team (never started,
	// stopped, or expired).
	InstanceStopped = "stopped"
	// InstanceBusy: the instancer refused for capacity or a rate limit;
	// retry after RetryAfter seconds when set.
	InstanceBusy = "busy"
	// InstanceUnknown: the platform cannot tell (e.g. no session to ask with).
	InstanceUnknown = "unknown"
	// InstanceError: the platform reported a failure; see Message.
	InstanceError = "error"
)

// InstanceStates lists every valid Instance.State.
var InstanceStates = []string{InstanceRunning, InstancePending, InstanceStopped, InstanceBusy, InstanceUnknown, InstanceError}

// Instance is the state of a per-team challenge instance after an action.
type Instance struct {
	Challenge string `json:"challenge"`
	Backend   string `json:"backend,omitempty"`
	// Action is the action that produced this state.
	Action string `json:"action"`
	// State is one of InstanceStates.
	State string `json:"state"`
	// Connect is how to reach a running instance.
	Connect *Connect `json:"connect,omitempty"`
	// Expires is when the instance stops on its own (RFC 3339 UTC), if known.
	Expires    string `json:"expires,omitempty"`
	Owner      string `json:"owner,omitempty"`
	RetryAfter int    `json:"retry_after_seconds,omitempty"`
	Message    string `json:"message,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// Connect is how to reach a target. Host is "host" or "host:port"; URL is set
// for web targets; Command is a ready-to-run client line (nc, openssl, ...).
// At least one of Host or URL is set.
type Connect struct {
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	URL     string `json:"url,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	Command string `json:"command,omitempty"`
}

// DownloadRequest tells the core how to fetch an attachment. Drivers attach
// auth headers; the core performs the transfer and writes the file.
type DownloadRequest struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Capabilities advertises which optional operations a driver supports.
type Capabilities struct {
	Challenges bool `json:"challenges"`
	Submit     bool `json:"submit"`
	Solves     bool `json:"solves"`
	Scoreboard bool `json:"scoreboard"`
	Team       bool `json:"team"`
	Download   bool `json:"download"`
	Hints      bool `json:"hints"`
	UnlockHint bool `json:"unlock_hint"`
	Instances  bool `json:"instances"`
	// InstanceActions lists the instance actions the platform supports, a
	// subset of InstanceActions (status is implied by Instances).
	InstanceActions []string `json:"instance_actions,omitempty"`
	// MaxInstances is how many instances the team may run at once (0 = unknown).
	MaxInstances int `json:"max_instances,omitempty"`
}

// Supports reports whether action is an advertised instance action.
func (c Capabilities) Supports(action string) bool {
	if !c.Instances {
		return false
	}
	if action == InstanceStatus {
		return true
	}
	for _, a := range c.InstanceActions {
		if a == action {
			return true
		}
	}
	return false
}

// Driver is one CTF platform. Unsupported operations return an *Error with
// KindUnsupported; embed Unsupported to get that behavior for free.
type Driver interface {
	Capabilities() Capabilities
	ListChallenges(ctx context.Context) ([]Challenge, error)
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	Submit(ctx context.Context, id, flag string) (*SubmitResult, error)
	Solves(ctx context.Context) ([]Solve, error)
	Scoreboard(ctx context.Context, q ScoreboardQuery) (*Scoreboard, error)
	Team(ctx context.Context) (*TeamStatus, error)
	PrepareDownload(ctx context.Context, fileURL string) (*DownloadRequest, error)
	Hints(ctx context.Context, challengeID string) ([]Hint, error)
	UnlockHint(ctx context.Context, hintID string) (*Hint, error)
	Instance(ctx context.Context, action, challenge string) (*Instance, error)
}

// Instance actions.
const (
	InstanceStatus = "status"
	InstanceStart  = "start"
	InstanceExtend = "extend"
	InstanceStop   = "stop"
	// InstanceReset recreates the instance with fresh state. Drivers whose
	// platform has no reset get it as stop then start (see ResetByRestart).
	InstanceReset = "reset"
)

// InstanceActions lists every instance action.
var InstanceActions = []string{InstanceStatus, InstanceStart, InstanceExtend, InstanceStop, InstanceReset}

// Unsupported implements every Driver method as unsupported.
type Unsupported struct{}

func unsupported(op string) error {
	return Errorf(KindUnsupported, "%s is not supported by this platform", op)
}

func (Unsupported) Capabilities() Capabilities { return Capabilities{} }
func (Unsupported) ListChallenges(context.Context) ([]Challenge, error) {
	return nil, unsupported("listing challenges")
}
func (Unsupported) GetChallenge(context.Context, string) (*Challenge, error) {
	return nil, unsupported("reading a challenge")
}
func (Unsupported) Submit(context.Context, string, string) (*SubmitResult, error) {
	return nil, unsupported("flag submission")
}
func (Unsupported) Solves(context.Context) ([]Solve, error) {
	return nil, unsupported("solve history")
}
func (Unsupported) Scoreboard(context.Context, ScoreboardQuery) (*Scoreboard, error) {
	return nil, unsupported("scoreboard")
}
func (Unsupported) Team(context.Context) (*TeamStatus, error) {
	return nil, unsupported("team status")
}
func (Unsupported) PrepareDownload(context.Context, string) (*DownloadRequest, error) {
	return nil, unsupported("file download")
}
func (Unsupported) Hints(context.Context, string) ([]Hint, error) {
	return nil, unsupported("hints")
}
func (Unsupported) UnlockHint(context.Context, string) (*Hint, error) {
	return nil, unsupported("hint unlock")
}
func (Unsupported) Instance(context.Context, string, string) (*Instance, error) {
	return nil, unsupported("challenge instances")
}

// Kind classifies errors so the CLI can map them to exit codes.
type Kind string

const (
	KindUsage  Kind = "usage"
	KindConfig Kind = "config"
	// KindAuth: the credentials are wrong or not allowed (fix the profile).
	KindAuth Kind = "auth"
	// KindExpired: the credentials were accepted before but the session has
	// expired (refresh the cookie/token, e.g. by signing in again).
	KindExpired     Kind = "expired"
	KindUnsupported Kind = "unsupported"
	KindNotFound    Kind = "not_found"
	// KindTimeout: the platform or driver did not answer in time.
	KindTimeout Kind = "timeout"
	KindRemote  Kind = "remote"
)

// Kinds lists every error kind.
var Kinds = []Kind{KindUsage, KindConfig, KindAuth, KindExpired, KindUnsupported, KindNotFound, KindTimeout, KindRemote}

// Error is a classified error.
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf builds a classified error.
func Errorf(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// KindOf returns the error's kind, or "" for unclassified errors.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}
