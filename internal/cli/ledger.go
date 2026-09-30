package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// ledgerRecord is one recorded flag submission. The flag itself is never
// stored, only its hash, so the ledger is safe to keep in the workspace.
type ledgerRecord struct {
	Platform  string `json:"platform"`
	Profile   string `json:"profile,omitempty"`
	Challenge string `json:"challenge"`
	FlagSHA   string `json:"flag_sha256"`
	Status    string `json:"status"`
	At        string `json:"at"`
}

func ledgerPath(root string) string {
	return filepath.Join(root, config.Dir, "submissions.jsonl")
}

func flagHash(flag string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(flag)))
	return hex.EncodeToString(sum[:])
}

// readLedger returns all recorded submissions, newest last. Errors are treated
// as an empty ledger: it is an optimisation, not a source of truth.
func readLedger(root string) []ledgerRecord {
	f, err := os.Open(ledgerPath(root))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []ledgerRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r ledgerRecord
		if json.Unmarshal([]byte(line), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func appendLedger(root string, r ledgerRecord) error {
	dir := filepath.Join(root, config.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(ledgerPath(root), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(r)
	_, err = f.Write(append(b, '\n'))
	return err
}

// priorCorrect finds an earlier accepted submission of the same flag on the
// same platform/profile, regardless of which challenge it was for.
func priorCorrect(root, platform, profile, hash string) (ledgerRecord, bool) {
	var found ledgerRecord
	var ok bool
	for _, r := range readLedger(root) {
		if r.Platform == platform && r.Profile == profile && r.FlagSHA == hash &&
			(r.Status == ctf.StatusCorrect || r.Status == ctf.StatusAlreadySolved) {
			found, ok = r, true
		}
	}
	return found, ok
}

// priorRejected finds an earlier rejected submission of the same flag for the
// same challenge, so an identical wrong flag is not sent again.
func priorRejected(root, platform, profile, hash string, challenges ...string) (ledgerRecord, bool) {
	want := map[string]bool{}
	for _, c := range challenges {
		if c != "" {
			want[c] = true
		}
	}
	var found ledgerRecord
	var ok bool
	for _, r := range readLedger(root) {
		if r.Platform == platform && r.Profile == profile && r.FlagSHA == hash &&
			r.Status == ctf.StatusIncorrect && want[r.Challenge] {
			found, ok = r, true
		}
	}
	return found, ok
}

// runOracle runs a local verify command before a flag is submitted. The flag
// is available as {flag} in the command and as $FLAG / $CANDIDATE in the
// environment. Exit 0 accepts; anything else blocks the submission.
func runOracle(ctx context.Context, command, flag, dir string) (bool, string, error) {
	cmd := command
	if strings.Contains(cmd, "{flag}") {
		cmd = strings.ReplaceAll(cmd, "{flag}", shellQuote(flag))
	}
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Dir = dir
	c.Env = append(os.Environ(), "FLAG="+flag, "CANDIDATE="+flag)
	out, err := c.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 2000 {
		text = text[:2000] + "..."
	}
	if err != nil {
		if _, isExit := err.(*exec.ExitError); isExit {
			return false, text, nil
		}
		return false, text, ctf.Errorf(ctf.KindUsage, "oracle failed to run: %v", err)
	}
	return true, text, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }
