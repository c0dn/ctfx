package ctf

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	ncRe       = regexp.MustCompile(`\b(?:nc|ncat|netcat)\s+(?:-\S+\s+)*([A-Za-z0-9.\-]+)\s+(\d{1,5})\b`)
	sClientRe  = regexp.MustCompile(`openssl\s+s_client\b.*?-connect\s+([A-Za-z0-9.\-]+):(\d{1,5})`)
	urlRe      = regexp.MustCompile(`\b(?:https?|wss?)://[^\s<>"'` + "`" + `)]+`)
	hostPortRe = regexp.MustCompile(`\b((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b`)
)

// ParseConnect turns free connection text ("nc host 1337", a URL, "host:port",
// an openssl s_client line) into a Connect. It returns nil when the text names
// no target.
func ParseConnect(text string) *Connect {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if m := sClientRe.FindStringSubmatch(text); m != nil {
		p, _ := strconv.Atoi(m[2])
		return &Connect{Host: net.JoinHostPort(m[1], m[2]), Port: p, TLS: true, Command: strings.TrimSpace(m[0])}
	}
	if m := ncRe.FindStringSubmatch(text); m != nil {
		p, _ := strconv.Atoi(m[2])
		return &Connect{Host: net.JoinHostPort(m[1], m[2]), Port: p, Command: "nc " + m[1] + " " + m[2]}
	}
	if m := urlRe.FindString(text); m != "" {
		return URLConnect(strings.TrimRight(m, ".,;"))
	}
	if m := hostPortRe.FindStringSubmatch(text); m != nil {
		return HostPortConnect(m[1], m[2])
	}
	return nil
}

// URLConnect builds a Connect for a web or WebSocket URL.
func URLConnect(raw string) *Connect {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	c := &Connect{URL: raw, Host: u.Host, TLS: u.Scheme == "https" || u.Scheme == "wss"}
	if p := u.Port(); p != "" {
		c.Port, _ = strconv.Atoi(p)
	} else if c.TLS {
		c.Port = 443
	} else {
		c.Port = 80
	}
	return c
}

// HostPortConnect builds a plain-TCP Connect for host and port.
func HostPortConnect(host, port string) *Connect {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || p <= 0 || p > 65535 || host == "" {
		if host == "" {
			return nil
		}
		return &Connect{Host: host}
	}
	return &Connect{Host: net.JoinHostPort(host, strconv.Itoa(p)), Port: p, Command: "nc " + host + " " + strconv.Itoa(p)}
}

// Timestamp normalizes a platform time to RFC 3339 UTC. It accepts RFC 3339
// (with or without zone), "2006-01-02 15:04:05", Unix seconds and Unix
// milliseconds, as a string or number. Unknown input yields "".
func Timestamp(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case time.Time:
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	case float64:
		return unixTime(int64(t))
	case int64:
		return unixTime(t)
	case int:
		return unixTime(int64(t))
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return ""
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return unixTime(n)
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
			if tm, err := time.Parse(layout, s); err == nil {
				return tm.UTC().Format(time.RFC3339)
			}
		}
	}
	return ""
}

func unixTime(n int64) string {
	if n <= 0 {
		return ""
	}
	if n > 1e12 { // milliseconds
		return time.UnixMilli(n).UTC().Format(time.RFC3339)
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// ExpiresIn returns the RFC 3339 UTC time d from now.
func ExpiresIn(d time.Duration) string {
	return time.Now().UTC().Add(d).Format(time.RFC3339)
}

// ResetByRestart implements reset as stop then start, for platforms with no
// reset of their own.
func ResetByRestart(ctx context.Context, d Driver, challenge string) (*Instance, error) {
	stop, err := d.Instance(ctx, InstanceStop, challenge)
	if err != nil {
		return nil, err
	}
	if stop.State == InstanceError || stop.State == InstanceBusy {
		stop.Action = InstanceReset
		return stop, nil
	}
	inst, err := d.Instance(ctx, InstanceStart, challenge)
	if inst != nil {
		inst.Action = InstanceReset
	}
	return inst, err
}

// ValidateInstance reports a contract violation in inst, or nil.
func ValidateInstance(inst *Instance) error {
	if inst == nil {
		return fmt.Errorf("instance: missing result")
	}
	if !slices.Contains(InstanceStates, inst.State) {
		return fmt.Errorf("instance: state %q is not one of %s", inst.State, strings.Join(InstanceStates, ", "))
	}
	if !slices.Contains(InstanceActions, inst.Action) {
		return fmt.Errorf("instance: action %q is not one of %s", inst.Action, strings.Join(InstanceActions, ", "))
	}
	if inst.State == InstanceRunning && (inst.Connect == nil || (inst.Connect.Host == "" && inst.Connect.URL == "")) {
		return fmt.Errorf("instance: running without connect.host or connect.url")
	}
	if inst.Expires != "" {
		if _, err := time.Parse(time.RFC3339, inst.Expires); err != nil {
			return fmt.Errorf("instance: expires %q is not RFC 3339", inst.Expires)
		}
	}
	return validateConnect("instance", inst.Connect)
}

// ValidateSubmit reports a contract violation in r, or nil.
func ValidateSubmit(r *SubmitResult) error {
	if r == nil {
		return fmt.Errorf("submit: missing result")
	}
	if !slices.Contains(SubmitStatuses, r.Status) {
		return fmt.Errorf("submit: status %q is not one of %s", r.Status, strings.Join(SubmitStatuses, ", "))
	}
	if r.Correct != (r.Status == StatusCorrect) {
		return fmt.Errorf("submit: correct=%v disagrees with status %q", r.Correct, r.Status)
	}
	return nil
}

// ValidateChallenge reports a contract violation in c, or nil.
func ValidateChallenge(c *Challenge) error {
	if c == nil {
		return fmt.Errorf("challenge: missing result")
	}
	if c.ID == "" || c.Name == "" {
		return fmt.Errorf("challenge: id and name are required (got id %q, name %q)", c.ID, c.Name)
	}
	for _, h := range c.Hints {
		if h.ID == "" {
			return fmt.Errorf("challenge %s: hint without id", c.ID)
		}
		if !h.Locked && h.Content == nil {
			return fmt.Errorf("challenge %s: hint %s is unlocked but has no content", c.ID, h.ID)
		}
	}
	if c.Limits != nil && c.Limits.Deadline != "" {
		if _, err := time.Parse(time.RFC3339, c.Limits.Deadline); err != nil {
			return fmt.Errorf("challenge %s: limits.deadline %q is not RFC 3339", c.ID, c.Limits.Deadline)
		}
	}
	return validateConnect("challenge "+c.ID, c.Connection)
}

func validateConnect(what string, c *Connect) error {
	if c == nil {
		return nil
	}
	if c.Host == "" && c.URL == "" {
		return fmt.Errorf("%s: connect needs host or url", what)
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("%s: connect.port %d out of range", what, c.Port)
	}
	return nil
}
