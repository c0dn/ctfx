package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/internal/drivers"
	"github.com/c0dn/ctfx/pkg/ctf"
)

func table(w io.Writer, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

func pts(f *float64) string {
	if f == nil {
		return "-"
	}
	return strconv.FormatFloat(*f, 'f', -1, 64)
}

func intStr(i *int) string {
	if i == nil {
		return "-"
	}
	return strconv.Itoa(*i)
}

func check(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

func (a *App) cmdPlatforms(args []string) error {
	fs := a.flags("platforms")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	root, err := a.root()
	if err != nil {
		return err
	}
	all := drivers.All(config.FindRoot(root))
	return a.emit(nil, map[string]any{"platforms": all}, func(w io.Writer) {
		rows := [][]string{{"NAME", "KIND", "DESCRIPTION"}}
		for _, s := range all {
			rows = append(rows, []string{s.Name, s.Kind, s.Description})
		}
		table(w, rows)
	})
}

func (a *App) cmdCaps(args []string) error {
	if _, err := parse(a.flags("caps"), args); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	caps := s.drv.Capabilities()
	return a.emit(s, map[string]any{"capabilities": caps}, nil)
}

func (a *App) cmdChalList(ctx context.Context, args []string) error {
	fs := a.flags("chal ls")
	category := fs.String("category", "", "exact category (case-insensitive)")
	unsolved := fs.Bool("unsolved", false, "only unsolved")
	solved := fs.Bool("solved", false, "only solved")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	list, err := s.drv.ListChallenges(ctx)
	if err != nil {
		return err
	}
	out := []ctf.Challenge{}
	for _, c := range list {
		if *category != "" && !strings.EqualFold(strings.TrimSpace(c.Category), strings.TrimSpace(*category)) {
			continue
		}
		if (*unsolved && c.Solved) || (*solved && !c.Solved) {
			continue
		}
		c.Description, c.Hints = "", nil // keep list output small; use chal show
		out = append(out, c)
	}
	return a.emit(s, map[string]any{"total": len(out), "challenges": out}, func(w io.Writer) {
		rows := [][]string{{"ID", "CATEGORY", "POINTS", "SOLVES", "SOLVED", "NAME"}}
		for _, c := range out {
			rows = append(rows, []string{c.ID, c.Category, pts(c.Points), intStr(c.Solves), check(c.Solved), c.Name})
		}
		table(w, rows)
	})
}

func (a *App) cmdChalShow(ctx context.Context, args []string) error {
	pos, err := parse(a.flags("chal show"), args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "chal show <id|name>"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	ch, err := a.challenge(ctx, s, pos[0])
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"challenge": ch}, func(w io.Writer) {
		fmt.Fprintf(w, "%s  [%s, %s pts, id %s]", ch.Name, ch.Category, pts(ch.Points), ch.ID)
		if ch.Solved {
			fmt.Fprint(w, "  SOLVED")
		}
		fmt.Fprintln(w)
		if ch.Author != "" {
			fmt.Fprintln(w, "author:", ch.Author)
		}
		if ch.Connection != "" {
			fmt.Fprintln(w, "connection:", ch.Connection)
		}
		if ch.Instance != nil {
			fmt.Fprintf(w, "instance: %s (%s) - `ctfx instance start %s`\n", ch.Instance.Slug, ch.Instance.Backend, ch.ID)
		}
		if ch.Description != "" {
			fmt.Fprintln(w, "\n"+strings.TrimSpace(ch.Description))
		}
		if len(ch.Files) > 0 {
			fmt.Fprintln(w, "\nfiles:")
			for _, f := range ch.Files {
				fmt.Fprintf(w, "  %s  %s\n", f.Name, f.URL)
			}
		}
		if len(ch.Hints) > 0 {
			fmt.Fprintln(w, "\nhints:")
			for _, h := range ch.Hints {
				state := "unlocked"
				if h.Locked {
					state = fmt.Sprintf("locked, cost %v", h.Cost)
				}
				fmt.Fprintf(w, "  #%s (%s) %s\n", h.ID, state, h.Title)
			}
		}
	})
}

func (a *App) cmdChalFiles(ctx context.Context, args []string) error {
	pos, err := parse(a.flags("chal files"), args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "chal files <id|name>"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	ch, err := a.challenge(ctx, s, pos[0])
	if err != nil {
		return err
	}
	files := ch.Files
	if files == nil {
		files = []ctf.File{}
	}
	return a.emit(s, map[string]any{"challenge_id": ch.ID, "files": files}, func(w io.Writer) {
		for _, f := range files {
			fmt.Fprintf(w, "%s\t%s\n", f.Name, f.URL)
		}
	})
}

func (a *App) cmdHints(ctx context.Context, args []string) error {
	pos, err := parse(a.flags("hint ls"), args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "hint ls <id|name>"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	id := pos[0]
	hints, err := s.drv.Hints(ctx, id)
	if k := ctf.KindOf(err); k == ctf.KindNotFound || k == ctf.KindUsage {
		if rid, rerr := resolve(ctx, s.drv, id); rerr == nil && rid != id {
			id = rid
			hints, err = s.drv.Hints(ctx, id)
		}
	}
	if err != nil {
		return err
	}
	if hints == nil {
		hints = []ctf.Hint{}
	}
	return a.emit(s, map[string]any{"challenge_id": id, "hints": hints}, func(w io.Writer) {
		rows := [][]string{{"HINT", "COST", "LOCKED", "TITLE/CONTENT"}}
		for _, h := range hints {
			text := h.Title
			if h.Content != nil {
				text = *h.Content
			}
			rows = append(rows, []string{h.ID, fmt.Sprint(h.Cost), check(h.Locked), text})
		}
		table(w, rows)
	})
}

func (a *App) cmdHintUnlock(ctx context.Context, args []string) error {
	pos, err := parse(a.flags("hint-unlock"), args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "hint-unlock <hint-id>"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	h, err := s.drv.UnlockHint(ctx, pos[0])
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"hint": h}, nil)
}

func (a *App) cmdSolves(ctx context.Context, args []string) error {
	if _, err := parse(a.flags("solves"), args); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	solves, err := s.drv.Solves(ctx)
	if err != nil {
		return err
	}
	if solves == nil {
		solves = []ctf.Solve{}
	}
	return a.emit(s, map[string]any{"total": len(solves), "solves": solves}, func(w io.Writer) {
		rows := [][]string{{"ID", "CATEGORY", "POINTS", "DATE", "NAME"}}
		for _, v := range solves {
			rows = append(rows, []string{v.ChallengeID, v.Category, pts(v.Points), v.Date, v.Name})
		}
		table(w, rows)
	})
}

func (a *App) cmdScoreboard(ctx context.Context, args []string) error {
	fs := a.flags("scoreboard")
	limit := fs.Int("limit", 10, "rows to return")
	offset := fs.Int("offset", 0, "starting offset")
	division := fs.String("division", "", "division/bracket filter")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *limit <= 0 || *offset < 0 {
		return usageError("--limit must be positive and --offset non-negative")
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	sb, err := s.drv.Scoreboard(ctx, ctf.ScoreboardQuery{Limit: *limit, Offset: *offset, Division: *division})
	if err != nil {
		return err
	}
	if sb.Entries == nil {
		sb.Entries = []ctf.ScoreEntry{}
	}
	return a.emit(s, map[string]any{"total": sb.Total, "offset": *offset, "limit": *limit, "entries": sb.Entries}, func(w io.Writer) {
		rows := [][]string{{"POS", "SCORE", "NAME"}}
		for _, e := range sb.Entries {
			rows = append(rows, []string{strconv.Itoa(e.Position), strconv.FormatFloat(e.Score, 'f', -1, 64), e.Name})
		}
		table(w, rows)
	})
}

func (a *App) cmdTeam(ctx context.Context, args []string) error {
	if _, err := parse(a.flags("team"), args); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	ts, err := s.drv.Team(ctx)
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"user": ts.User, "team": ts.Team, "team_error": ts.TeamError}, nil)
}

func (a *App) cmdInstance(ctx context.Context, action string, args []string) error {
	switch action {
	case ctf.InstanceStatus, ctf.InstanceStart, ctf.InstanceExtend, ctf.InstanceStop:
	default:
		return usageError("usage: ctfx instance status|start|extend|stop <id|slug>")
	}
	pos, err := parse(a.flags("instance "+action), args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "instance "+action+" <id|slug>"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	inst, err := s.drv.Instance(ctx, action, pos[0])
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"instance": inst}, nil)
}

// readFlag reads a flag from stdin, dropping one trailing newline.
func readFlag(r io.Reader) (string, error) {
	b, err := io.ReadAll(bufio.NewReader(io.LimitReader(r, 1<<20)))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

func (a *App) cmdSubmit(ctx context.Context, args []string) error {
	fs := a.flags("submit")
	force := fs.Bool("force", false, "submit even if this flag was already recorded as incorrect")
	verify := fs.String("verify", "", "local oracle command run before submitting; {flag} is substituted, $FLAG/$CANDIDATE are set; a non-zero exit blocks the submission")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return usageError("usage: ctfx submit <id|name> [flag|-] [--verify CMD] [--force]   (reads the flag from stdin when omitted or -)")
	}
	flagValue := ""
	if len(pos) == 2 && pos[1] != "-" {
		flagValue = pos[1]
	} else {
		if flagValue, err = readFlag(a.Stdin); err != nil {
			return err
		}
	}
	if strings.TrimSpace(flagValue) == "" {
		return usageError("empty flag")
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	id := pos[0]
	hash := flagHash(flagValue)

	// Ledger: never resubmit a flag already known correct, and refuse an
	// identical wrong flag unless forced (both save rate limit / penalties).
	if rec, ok := priorCorrect(s.cfg.Root, s.cfg.Platform, s.cfg.Profile, hash); ok {
		res := &ctf.SubmitResult{ChallengeID: id, Status: rec.Status, Correct: rec.Status == ctf.StatusCorrect,
			Message: "known from an earlier submission on " + rec.At + " (ledger); not re-sent"}
		return a.emitSubmit(s, res)
	}
	if !*force {
		if rec, ok := priorRejected(s.cfg.Root, s.cfg.Platform, s.cfg.Profile, hash, id); ok {
			return usageError("this flag was already submitted for %q and rejected on %s; use --force to send it again", id, rec.At)
		}
	}
	if *verify != "" {
		ok, out, oerr := runOracle(ctx, *verify, flagValue, a.opts.Dir)
		if oerr != nil {
			return oerr
		}
		if !ok {
			res := &ctf.SubmitResult{ChallengeID: id, Status: ctf.StatusError, Message: "local oracle rejected the flag: " + out}
			return a.emitSubmit(s, res)
		}
	}

	res, err := s.drv.Submit(ctx, id, flagValue)
	k := ctf.KindOf(err)
	if k == ctf.KindNotFound || k == ctf.KindUsage || (err == nil && res.Status == ctf.StatusBadChallenge) {
		if rid, rerr := resolve(ctx, s.drv, id); rerr == nil && rid != id {
			res, err = s.drv.Submit(ctx, rid, flagValue)
		}
	}
	if err != nil {
		return err
	}
	// Record real verdicts so future runs can short-circuit or refuse.
	if res.Status == ctf.StatusCorrect || res.Status == ctf.StatusIncorrect || res.Status == ctf.StatusAlreadySolved {
		challenge := res.ChallengeID
		if challenge == "" {
			challenge = id
		}
		_ = appendLedger(s.cfg.Root, ledgerRecord{Platform: s.cfg.Platform, Profile: s.cfg.Profile,
			Challenge: challenge, FlagSHA: hash, Status: res.Status, At: nowUTC()})
	}
	return a.emitSubmit(s, res)
}

func (a *App) emitSubmit(s *session, res *ctf.SubmitResult) error {
	return a.emit(s, map[string]any{"result": res}, func(w io.Writer) {
		fmt.Fprintf(w, "%s: %s", res.ChallengeID, strings.ToUpper(res.Status))
		if res.Message != "" {
			fmt.Fprintf(w, " - %s", res.Message)
		}
		fmt.Fprintln(w)
	})
}

var slugRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// Slug makes a filesystem-friendly directory name.
func Slug(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-"), "-.")
	if s == "" {
		return "unnamed"
	}
	return s
}

var categoryAliases = map[string]string{
	"rev": "reversing", "re": "reversing", "reverse": "reversing", "reverse-engineering": "reversing",
	"reverse engineering": "reversing", "binary-exploitation": "pwn", "binary exploitation": "pwn",
	"pwnable": "pwn", "exploitation": "pwn", "forensic": "forensics", "cryptography": "crypto",
	"web-exploitation": "web", "web exploitation": "web", "miscellaneous": "misc",
	"machine-learning": "ml", "ai": "ml", "hardware": "iot",
}

// Category normalizes a platform category to the workspace layout.
func Category(c string) string {
	k := strings.ToLower(strings.TrimSpace(c))
	if v, ok := categoryAliases[k]; ok {
		return v
	}
	if k == "" {
		return "misc"
	}
	return Slug(k)
}

func (a *App) challengeDir(root, base string, ch *ctf.Challenge) string {
	return filepath.Join(root, base, Category(ch.Category), Slug(ch.Name))
}

func (a *App) fetchFiles(ctx context.Context, s *session, ch *ctf.Challenge, dest string, force bool) ([]*core.Downloaded, error) {
	out := []*core.Downloaded{}
	for _, f := range ch.Files {
		dr, err := s.drv.PrepareDownload(ctx, f.URL)
		if err != nil {
			return out, err
		}
		d, err := core.Download(ctx, s.client, dr, core.SaveOptions{Root: s.cfg.Root, Dest: dest + string(filepath.Separator), Name: f.Name, SkipExisting: !force})
		if err != nil {
			return out, fmt.Errorf("%s: %w", f.Name, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func (a *App) cmdFetch(ctx context.Context, args []string) error {
	fs := a.flags("fetch")
	dest := fs.String("o", "", "destination directory (default challenges/<cat>/<name>/dist)")
	force := fs.Bool("force", false, "overwrite existing files")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "fetch <id|name> [-o DIR] [--force]"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	ch, err := a.challenge(ctx, s, pos[0])
	if err != nil {
		return err
	}
	dir := *dest
	if dir == "" {
		dir = filepath.Join(a.challengeDir(s.cfg.Root, "challenges", ch), "dist")
	}
	files, err := a.fetchFiles(ctx, s, ch, dir, *force)
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"challenge_id": ch.ID, "dir": dir, "files": files}, func(w io.Writer) {
		for _, f := range files {
			state := "saved"
			if f.Skipped {
				state = "exists"
			}
			fmt.Fprintf(w, "%-7s %s (%d bytes)\n", state, f.SavedTo, f.SizeBytes)
		}
	})
}

func (a *App) cmdDownload(ctx context.Context, args []string) error {
	fs := a.flags("download")
	dest := fs.String("o", "", "destination file or directory (default: current directory)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "download <url> [-o PATH]"); err != nil {
		return err
	}
	s, err := a.open()
	if err != nil {
		return err
	}
	dr, err := s.drv.PrepareDownload(ctx, pos[0])
	if err != nil {
		return err
	}
	d, err := core.Download(ctx, s.client, dr, core.SaveOptions{Root: s.cfg.Root, Dest: *dest})
	if err != nil {
		return err
	}
	return a.emit(s, map[string]any{"file": d}, nil)
}

const descName = "desc.md"

func renderDesc(platform string, ch *ctf.Challenge) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", ch.Name)
	fmt.Fprintf(&b, "- Category: %s\n- Points: %s\n- ID: %s\n- Platform: %s\n", ch.Category, pts(ch.Points), ch.ID, platform)
	if ch.Author != "" {
		fmt.Fprintf(&b, "- Author: %s\n", ch.Author)
	}
	if ch.Connection != "" {
		fmt.Fprintf(&b, "- Connection: `%s`\n", ch.Connection)
	}
	if ch.Instance != nil {
		fmt.Fprintf(&b, "- Instance: %s (`ctfx instance start %s`)\n", ch.Instance.Backend, ch.ID)
	}
	fmt.Fprintf(&b, "\n## Description\n\n%s\n", strings.TrimSpace(ch.Description))
	if len(ch.Files) > 0 {
		b.WriteString("\n## Files\n\n")
		for _, f := range ch.Files {
			fmt.Fprintf(&b, "- `dist/%s`\n", core.SanitizeFilename(f.Name))
		}
	}
	if len(ch.Hints) > 0 {
		b.WriteString("\n## Hints\n\n")
		for _, h := range ch.Hints {
			if h.Content != nil {
				fmt.Fprintf(&b, "- #%s: %s\n", h.ID, *h.Content)
			} else {
				fmt.Fprintf(&b, "- #%s: locked (cost %v)\n", h.ID, h.Cost)
			}
		}
	}
	return b.String()
}

type syncEntry struct {
	ID    string             `json:"id"`
	Name  string             `json:"name"`
	Dir   string             `json:"dir"`
	Desc  string             `json:"desc"` // created, updated, unchanged, kept
	Files []*core.Downloaded `json:"files,omitempty"`
	Error string             `json:"error,omitempty"`
}

type syncOpts struct {
	base, category                string
	unsolved, noFiles, updateDesc bool
}

func (a *App) cmdSync(ctx context.Context, args []string) error {
	fs := a.flags("sync")
	base := fs.String("dir", "challenges", "challenges directory, relative to the workspace root")
	category := fs.String("category", "", "only this category")
	unsolved := fs.Bool("unsolved", false, "only unsolved challenges")
	noFiles := fs.Bool("no-files", false, "skip attachment downloads")
	updateDesc := fs.Bool("update-desc", false, "rewrite existing desc.md files")
	watch := fs.Bool("watch", false, "keep syncing on an interval until interrupted")
	interval := fs.Int("interval", 300, "seconds between --watch passes")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	o := syncOpts{base: *base, category: *category, unsolved: *unsolved, noFiles: *noFiles, updateDesc: *updateDesc}

	if !*watch {
		s, entries, failed, err := a.syncPass(ctx, o)
		if err != nil {
			return err
		}
		err = a.emit(s, map[string]any{"total": len(entries), "failed": failed, "challenges": entries}, func(w io.Writer) {
			for _, e := range entries {
				printSyncEntry(w, s.cfg.Root, e)
			}
		})
		if err == nil && failed > 0 {
			return ctf.Errorf(ctf.KindRemote, "%d of %d challenges failed to sync", failed, len(entries))
		}
		return err
	}

	if *interval < 5 {
		*interval = 5
	}
	root, err := a.root()
	if err != nil {
		return err
	}
	release, err := acquireSyncLock(config.FindRoot(root))
	if err != nil {
		return err
	}
	defer release()
	fmt.Fprintf(a.Stderr, "watching every %ds; press Ctrl-C to stop\n", *interval)
	for {
		_, entries, failed, err := a.syncPass(ctx, o)
		if err != nil {
			fmt.Fprintf(a.Stderr, "%s  sync error: %v\n", nowUTC(), err)
		} else {
			fmt.Fprintf(a.Stdout, "%s  synced %d challenges, %d failed\n", nowUTC(), len(entries), failed)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(*interval) * time.Second):
		}
	}
}

// syncPass runs one sync over the current board and returns the session so the
// caller can emit platform context.
func (a *App) syncPass(ctx context.Context, o syncOpts) (*session, []syncEntry, int, error) {
	s, err := a.open()
	if err != nil {
		return nil, nil, 0, err
	}
	list, err := s.drv.ListChallenges(ctx)
	if err != nil {
		return s, nil, 0, err
	}
	entries := []syncEntry{}
	failed := 0
	for _, item := range list {
		if o.category != "" && !strings.EqualFold(item.Category, o.category) {
			continue
		}
		if o.unsolved && item.Solved {
			continue
		}
		e := syncEntry{ID: item.ID, Name: item.Name}
		if err := a.syncOne(ctx, s, item, o.base, o.noFiles, o.updateDesc, &e); err != nil {
			e.Error = err.Error()
			failed++
		}
		entries = append(entries, e)
	}
	return s, entries, failed, nil
}

func printSyncEntry(w io.Writer, root string, e syncEntry) {
	rel, _ := filepath.Rel(root, e.Dir)
	line := fmt.Sprintf("%-9s %s", e.Desc, rel)
	if n := len(e.Files); n > 0 {
		line += fmt.Sprintf(" (%d files)", n)
	}
	if e.Error != "" {
		line += "  ERROR: " + e.Error
	}
	fmt.Fprintln(w, line)
}

// acquireSyncLock takes a best-effort advisory lock so two watchers don't sync
// the same workspace at once. A lock left by a dead process is reclaimed.
func acquireSyncLock(root string) (func(), error) {
	dir := filepath.Join(root, config.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lock := filepath.Join(dir, "sync.lock")
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) && lockIsStale(lock) {
			_ = os.Remove(lock)
			return acquireSyncLock(root)
		}
		if os.IsExist(err) {
			return nil, ctf.Errorf(ctf.KindUsage, "another `ctfx sync --watch` is running (%s); remove it if not", lock)
		}
		return nil, err
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	return func() { _ = os.Remove(lock) }, nil
}

func lockIsStale(lock string) bool {
	b, err := os.ReadFile(lock)
	if err != nil {
		return true
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return true
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	return p.Signal(syscall.Signal(0)) != nil
}

func (a *App) syncOne(ctx context.Context, s *session, item ctf.Challenge, base string, noFiles, updateDesc bool, e *syncEntry) error {
	ch, err := s.drv.GetChallenge(ctx, item.ID)
	if err != nil {
		return err
	}
	e.Dir = a.challengeDir(s.cfg.Root, base, ch)
	if !core.InsideRoot(s.cfg.Root, e.Dir) {
		return ctf.Errorf(ctf.KindUsage, "refusing to write outside the workspace: %s", e.Dir)
	}
	if err := os.MkdirAll(e.Dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(e.Dir, descName)
	content := renderDesc(s.cfg.Platform, ch)
	old, readErr := os.ReadFile(path)
	switch {
	case readErr != nil:
		e.Desc = "created"
	case string(old) == content:
		e.Desc = "unchanged"
	case updateDesc:
		e.Desc = "updated"
	default:
		e.Desc = "kept"
	}
	if e.Desc == "created" || e.Desc == "updated" {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if !noFiles && len(ch.Files) > 0 {
		e.Files, err = a.fetchFiles(ctx, s, ch, filepath.Join(e.Dir, "dist"), false)
	}
	return err
}

func (a *App) cmdInit(ctx context.Context, args []string) error {
	fs := a.flags("init")
	force := fs.Bool("force", false, "overwrite an existing profile")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "init <platform|url> [--profile NAME] [--force]"); err != nil {
		return err
	}
	root, err := a.root()
	if err != nil {
		return err
	}

	target := pos[0]
	var spec driver.Spec
	var det *driver.Detection
	if strings.Contains(target, "://") {
		client := core.NewClient(core.ClientOptions{
			Verify:      true,
			Impersonate: os.Getenv("CTFX_IMPERSONATE"),
			UserAgent:   os.Getenv("CTFX_USER_AGENT"),
			Cookies:     os.Getenv("CTFX_COOKIES"),
		})
		var ok bool
		if spec, det, ok = drivers.Detect(ctx, client, target); !ok {
			return usageError("could not detect a supported platform at %s; run `ctfx init <platform>` and set the URL by hand", target)
		}
	} else {
		var ok bool
		if spec, ok = drivers.Lookup(root, target); !ok {
			return usageError("unknown platform %q (see `ctfx platforms`)", target)
		}
	}

	name := a.opts.Profile
	if name == "" {
		name = spec.Name
	}
	if Slug(name) != strings.ToLower(name) {
		return usageError("invalid profile name %q", name)
	}
	dir := filepath.Join(root, config.Dir)
	path := filepath.Join(dir, name+".env")
	if _, err := os.Stat(path); err == nil && !*force {
		return usageError("%s already exists (use --force to overwrite)", path)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	gi := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gi); err != nil {
		if err := os.WriteFile(gi, []byte("# ctfx profiles hold credentials\n*.env\n"), 0o644); err != nil {
			return err
		}
	}

	content := spec.Example
	if det != nil {
		kv := map[string]string{envPrefix(spec.Name) + "_URL": det.BaseURL}
		for k, v := range det.Values {
			kv[k] = v
		}
		content = fillEnv(content, kv)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	return a.emit(nil, map[string]any{"created": path, "platform": spec.Name, "profile": name, "detected": det != nil}, func(w io.Writer) {
		if det != nil {
			fmt.Fprintf(w, "created %s (detected %s at %s)\nadd your credentials, then run `ctfx caps`\n", path, spec.Name, det.BaseURL)
		} else {
			fmt.Fprintf(w, "created %s\nfill in the URL and credentials, then run `ctfx caps` and `ctfx chal ls`\n", path)
		}
	})
}

// envPrefix converts a platform name to its env-key prefix, eg "gzctf" -> "GZCTF".
func envPrefix(name string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

// fillEnv sets each KEY to its value in an env template, uncommenting a
// matching `# KEY=` line, replacing an existing `KEY=` line, or appending.
func fillEnv(example string, kv map[string]string) string {
	lines := strings.Split(example, "\n")
	done := map[string]bool{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		for k, v := range kv {
			if strings.HasPrefix(trimmed, k+"=") {
				lines[i] = fmt.Sprintf("%s=%q", k, v)
				done[k] = true
			}
		}
	}
	var add []string
	for k, v := range kv {
		if !done[k] {
			add = append(add, fmt.Sprintf("%s=%q", k, v))
		}
	}
	sort.Strings(add)
	if len(add) > 0 {
		out := strings.TrimRight(strings.Join(lines, "\n"), "\n")
		return out + "\n" + strings.Join(add, "\n") + "\n"
	}
	return strings.Join(lines, "\n")
}

func (a *App) cmdConfigShow(args []string) error {
	if _, err := parse(a.flags("config show"), args); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	spec, _ := drivers.Lookup(cfg.Root, cfg.Platform)
	root := cfg.Root
	payload := map[string]any{
		"root": root, "platform": cfg.Platform, "profile": cfg.Profile, "source": cfg.Source,
		"driver": spec, "values": cfg.Redacted(),
		"profiles": config.Profiles(root), "legacy_profiles": config.LegacyProfiles(root),
	}
	return a.emit(nil, payload, nil)
}

func (a *App) cmdConfigMigrate(args []string) error {
	if _, err := parse(a.flags("config migrate"), args); err != nil {
		return err
	}
	start, err := a.root()
	if err != nil {
		return err
	}
	root := config.FindRoot(start)
	type item struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Status string `json:"status"`
	}
	items := []item{}
	for _, name := range config.LegacyProfiles(root) {
		from := filepath.Join(root, config.LegacyDir, name+".env")
		to := filepath.Join(root, config.Dir, name+".env")
		it := item{From: from, To: to}
		if _, err := os.Stat(to); err == nil {
			it.Status = "exists"
			items = append(items, it)
			continue
		}
		body, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		vals, _ := config.ParseEnvFile(from)
		if _, ok := vals["CTFX_PLATFORM"]; !ok {
			body = append([]byte(fmt.Sprintf("CTFX_PLATFORM=%q\n", name)), body...)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		gi := filepath.Join(root, config.Dir, ".gitignore")
		if _, err := os.Stat(gi); err != nil {
			_ = os.WriteFile(gi, []byte("# ctfx profiles hold credentials\n*.env\n"), 0o644)
		}
		if err := os.WriteFile(to, body, 0o600); err != nil {
			return err
		}
		it.Status = "copied"
		items = append(items, it)
	}
	return a.emit(nil, map[string]any{"migrated": items}, nil)
}
