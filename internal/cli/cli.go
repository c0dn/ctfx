// Package cli implements the ctfx command line.
//
// Command layout keeps reads and writes apart so harness permission rules can
// allow reads and ask on writes by command prefix:
//
//	reads:  chal, hint ls, solves, scoreboard, team, instance status, caps, platforms, config show
//	writes: submit, hint-unlock, instance start|extend|stop, fetch, download, sync, init, config migrate
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/core"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/internal/drivers"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitConfig      = 3 // config or auth
	ExitUnsupported = 4
	ExitRemote      = 5 // remote error or not found
)

// App holds per-invocation state.
type App struct {
	Version string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	// IsTTY reports whether stdout is a terminal; JSON is the default otherwise.
	IsTTY bool

	opts   config.Options
	format string // json, table, or "" for auto
}

// usageError marks bad invocations.
func usageError(format string, args ...any) error { return ctf.Errorf(ctf.KindUsage, format, args...) }

const usageText = `ctfx - CTF platform client

Usage: ctfx [global flags] <command> [args]

Read commands:
  chal ls [--category C] [--unsolved|--solved]   list challenges
  chal show <id|name>                            challenge details
  chal files <id|name>                           attachment URLs
  hint ls <id|name>                              hints with lock state and cost
  solves                                         your solve history
  scoreboard [--limit N] [--offset N] [--division D]
  team                                           your user/team snapshot
  instance status <id|slug>                      per-team instance state
  caps                                           what this platform supports
  platforms                                      available drivers
  config show                                    resolved config (secrets masked)

Write commands (mutate remote or local state):
  submit <id|name> [flag|-]                      submit a flag (stdin when omitted or -)
  hint-unlock <hint-id>                          spend points to unlock a hint
  instance start|extend|stop <id|slug>           manage a per-team instance
  fetch <id|name> [-o DIR] [--force]             download a challenge's files
  download <url> [-o PATH]                       download one attachment URL
  sync [--dir challenges] [--category C] [--unsolved] [--no-files] [--update-desc] [--watch [--interval N]]
                                                 mirror challenges into challenges/<cat>/<name>/
  init <platform|url> [--profile NAME] [--force]  create .ctfx/<profile>.env (a URL is autodetected)
  config migrate                                 copy legacy .opencode/ctf/*.env into .ctfx/

Global flags:
  --profile NAME    profile (.ctfx/NAME.env); env CTFX_PROFILE
  --platform NAME   override the platform; env CTFX_PLATFORM
  -C DIR            run as if started in DIR
  --json            force JSON output (default when stdout is not a terminal)
  --format F        json or table

Environment: CTFX_IMPERSONATE=chrome|firefox|safari mimics a browser's TLS/HTTP
fingerprint to pass bot screening; CTFX_USER_AGENT and CTFX_COOKIES (eg a
cf_clearance value) tune it further. These also work per-platform (CTFD_*, etc).

Exit codes: 0 ok (including a wrong flag: check "status"), 1 error, 2 usage,
3 config/auth, 4 unsupported by platform, 5 remote error or not found.
`

// Run executes args and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.Stdout, usageText)
		return ExitOK
	}
	args, err := a.leadingGlobals(args)
	if err == nil {
		if len(args) == 0 {
			fmt.Fprint(a.Stdout, usageText)
			return ExitOK
		}
		err = a.dispatch(ctx, args)
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	return a.fail(err)
}

func (a *App) fail(err error) int {
	kind := ctf.KindOf(err)
	code := ExitError
	switch kind {
	case ctf.KindUsage:
		code = ExitUsage
	case ctf.KindConfig, ctf.KindAuth:
		code = ExitConfig
	case ctf.KindUnsupported:
		code = ExitUnsupported
	case ctf.KindNotFound, ctf.KindRemote:
		code = ExitRemote
	}
	if a.jsonOut() {
		if kind == "" {
			kind = "error"
		}
		b, _ := json.Marshal(map[string]any{"error": map[string]any{"kind": kind, "message": err.Error(), "exit_code": code}})
		fmt.Fprintln(a.Stderr, string(b))
	} else {
		fmt.Fprintln(a.Stderr, "ctfx:", err)
	}
	return code
}

func (a *App) jsonOut() bool {
	switch a.format {
	case "json":
		return true
	case "table", "text":
		return false
	}
	return !a.IsTTY
}

// leadingGlobals consumes global flags that appear before the command name.
func (a *App) leadingGlobals(args []string) ([]string, error) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" && args[0] != "--version" {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[0], "-"), "=")
		switch name {
		case "json":
			a.format = "json"
			args = args[1:]
			continue
		case "profile", "platform", "C", "format":
		case "h", "help":
			return nil, nil
		default:
			return nil, usageError("unknown global flag %q (see `ctfx --help`)", args[0])
		}
		args = args[1:]
		if !hasVal {
			if len(args) == 0 {
				return nil, usageError("flag -%s needs a value", name)
			}
			val, args = args[0], args[1:]
		}
		switch name {
		case "profile":
			a.opts.Profile = val
		case "platform":
			a.opts.Platform = val
		case "C":
			a.opts.Dir = val
		case "format":
			a.format = val
		}
	}
	return args, nil
}

// flags returns a FlagSet with the global flags attached.
func (a *App) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("ctfx "+name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.StringVar(&a.opts.Profile, "profile", a.opts.Profile, "profile name")
	fs.StringVar(&a.opts.Platform, "platform", a.opts.Platform, "platform override")
	fs.StringVar(&a.opts.Dir, "C", a.opts.Dir, "working directory")
	fs.StringVar(&a.format, "format", a.format, "json or table")
	fs.BoolFunc("json", "JSON output", func(string) error { a.format = "json"; return nil })
	return fs
}

// parse parses flags that may be interleaved with positional args.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for i, v := range args {
		if v == "--" {
			args, rest = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError("%v", err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return append(pos, rest...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func need(pos []string, n int, usage string) error {
	if len(pos) != n {
		return usageError("usage: ctfx %s", usage)
	}
	return nil
}

func (a *App) dispatch(ctx context.Context, args []string) error {
	cmd, rest := args[0], args[1:]
	sub := ""
	if len(rest) > 0 && (cmd == "chal" || cmd == "challenge" || cmd == "hint" || cmd == "instance" || cmd == "config") {
		sub, rest = rest[0], rest[1:]
	}
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(a.Stdout, "ctfx", a.Version)
		return nil
	case "platforms":
		return a.cmdPlatforms(rest)
	case "init":
		return a.cmdInit(ctx, rest)
	case "chal", "challenge":
		switch sub {
		case "ls", "list":
			return a.cmdChalList(ctx, rest)
		case "show", "get":
			return a.cmdChalShow(ctx, rest)
		case "files":
			return a.cmdChalFiles(ctx, rest)
		}
		return usageError("usage: ctfx chal ls|show|files")
	case "hint":
		if sub == "ls" || sub == "list" {
			return a.cmdHints(ctx, rest)
		}
		return usageError("usage: ctfx hint ls <challenge> (unlock with `ctfx hint-unlock <hint-id>`)")
	case "hint-unlock":
		return a.cmdHintUnlock(ctx, rest)
	case "solves":
		return a.cmdSolves(ctx, rest)
	case "scoreboard":
		return a.cmdScoreboard(ctx, rest)
	case "team":
		return a.cmdTeam(ctx, rest)
	case "instance":
		return a.cmdInstance(ctx, sub, rest)
	case "caps":
		return a.cmdCaps(rest)
	case "submit":
		return a.cmdSubmit(ctx, rest)
	case "fetch":
		return a.cmdFetch(ctx, rest)
	case "download":
		return a.cmdDownload(ctx, rest)
	case "sync":
		return a.cmdSync(ctx, rest)
	case "config":
		switch sub {
		case "show", "":
			return a.cmdConfigShow(rest)
		case "migrate":
			return a.cmdConfigMigrate(rest)
		}
		return usageError("usage: ctfx config show|migrate")
	}
	return usageError("unknown command %q (see `ctfx --help`)", cmd)
}

// session is an opened driver plus its config.
type session struct {
	cfg    *config.Config
	spec   driver.Spec
	drv    ctf.Driver
	client *http.Client
}

func (a *App) loadConfig() (*config.Config, error) {
	known := func(root, name string) bool { _, ok := drivers.Lookup(root, name); return ok }
	return config.Load(a.opts, known, drivers.Builtin())
}

func (a *App) open() (*session, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	spec, _ := drivers.Lookup(cfg.Root, cfg.Platform)
	client := core.NewClient(core.ClientOptions{
		Verify:      cfg.Bool("VERIFY_SSL", true),
		Impersonate: cfg.Get("IMPERSONATE"),
		UserAgent:   cfg.Get("USER_AGENT"),
		Cookies:     cfg.Get("COOKIES"),
	})
	drv, err := spec.New(&driver.Env{Config: cfg, Client: client})
	if err != nil {
		return nil, err
	}
	return &session{cfg: cfg, spec: spec, drv: drv, client: client}, nil
}

// emit writes payload as JSON (with platform context) or via human.
func (a *App) emit(s *session, payload map[string]any, human func(w io.Writer)) error {
	if a.jsonOut() || human == nil {
		if s != nil {
			payload["platform"] = s.cfg.Platform
			if s.cfg.Profile != "" {
				payload["profile"] = s.cfg.Profile
			}
		}
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(payload)
	}
	human(a.Stdout)
	return nil
}

// resolve maps a challenge name to its ID. Exact ID matches win; otherwise a
// unique case-insensitive name match is used; otherwise arg is returned.
func resolve(ctx context.Context, d ctf.Driver, arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", usageError("challenge must not be empty")
	}
	if !d.Capabilities().Challenges {
		return arg, nil
	}
	list, err := d.ListChallenges(ctx)
	if err != nil {
		return "", err
	}
	var byName []string
	for _, c := range list {
		if c.ID == arg {
			return arg, nil
		}
		if strings.EqualFold(c.Name, arg) {
			byName = append(byName, c.ID)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return arg, nil
	}
	return "", usageError("challenge name %q is ambiguous (IDs %s); pass an ID", arg, strings.Join(byName, ", "))
}

func (a *App) challenge(ctx context.Context, s *session, arg string) (*ctf.Challenge, error) {
	ch, err := s.drv.GetChallenge(ctx, arg)
	if k := ctf.KindOf(err); k == ctf.KindNotFound || k == ctf.KindUsage {
		id, rerr := resolve(ctx, s.drv, arg)
		if rerr != nil {
			return nil, rerr
		}
		if id != arg {
			return s.drv.GetChallenge(ctx, id)
		}
	}
	return ch, err
}

func (a *App) root() (string, error) {
	start := a.opts.Dir
	if start == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		start = wd
	}
	return filepath.Abs(start)
}
