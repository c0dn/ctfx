# ctfx

A small CLI for CTF platforms. You get one command set across CTFd, rCTF,
GZCTF and Hack The Box CTF, and any other platform can be added with an exec
plugin written in whatever language you like. The CLI is built for AI coding
agents as well as people: output is JSON whenever stdout is not a terminal,
exit codes are stable, and read commands and write commands are separate so
harness permission rules can tell them apart.

```sh
ctfx init https://demo.ctfd.io        # autodetect the platform, write .ctfx/ctfd.env (gitignored)
ctfx chal ls --unsolved               # table on a TTY, JSON when piped
ctfx chal show "baby rsa"             # IDs or exact names both work
ctfx fetch "baby rsa"                 # -> challenges/crypto/baby-rsa/dist/
printf '%s' 'flag{...}' | ctfx submit "baby rsa"
ctfx sync                             # mirror the board into challenges/<cat>/<name>/
```

## Install

```sh
npx @c0dn/ctfx --help                 # or: go install github.com/c0dn/ctfx/cmd/ctfx@latest
```

## Commands

| Kind  | Command | Notes |
|-------|---------|-------|
| read  | `chal ls [--category C] [--unsolved\|--solved]` | |
| read  | `chal show <id\|name>` / `chal files <id\|name>` | |
| read  | `hint ls <id\|name>` | lock state and cost |
| read  | `solves`, `team`, `scoreboard [--limit N --offset N --division D]` | |
| read  | `instance status <id\|slug>` | CTFd (KubeCTF/whale/owl/chall-manager) and GZCTF |
| read  | `caps`, `platforms`, `config show` | secrets are masked |
| write | `submit <id\|name> [flag\|-] [--verify CMD] [--force]` | flag from stdin when omitted or `-`; see the ledger below |
| write | `hint-unlock <hint-id>` | spends points |
| write | `instance start\|extend\|stop <id\|slug>` | |
| write | `fetch <id\|name> [-o DIR] [--force]`, `download <url> [-o PATH]` | writes stay inside the workspace |
| write | `sync [--dir D] [--category C] [--unsolved] [--no-files] [--update-desc] [--watch [--interval N]]` | never overwrites an existing `desc.md` unless `--update-desc`; `--watch` polls for new waves |
| write | `init <platform\|url> [--profile NAME]`, `config migrate` | a URL is autodetected; local files only |

Global flags: `--profile NAME`, `--platform NAME`, `-C DIR`, `--json`, `--format json|table`.

`submit` keeps a local ledger (`.ctfx/submissions.jsonl`, flag hashes only): it
never resends a flag already known correct, and refuses an identical wrong flag
unless you pass `--force`. `--verify CMD` runs a local oracle first (`{flag}` is
substituted, `$FLAG`/`$CANDIDATE` are set); a non-zero exit blocks the submission.

Exit codes: `0` ok (a wrong flag is also `0`: check `result.status`),
`1` error, `2` usage, `3` config or auth, `4` the platform does not support
the operation, `5` remote error or not found. In JSON mode, errors go to stderr
as `{"error":{"kind","message","exit_code"}}`.

Submit statuses: `correct`, `incorrect`, `already_solved`, `rate_limited`,
`bad_challenge`, `not_started`, `ended`, `error`.

## Configuration

ctfx walks up from the current directory looking for `.ctfx/`. Each
`.ctfx/<profile>.env` file is one profile. With a single profile it is picked
automatically; with more than one, choose with `--profile` or `CTFX_PROFILE`.
Keys use the platform's prefix (`CTFD_URL`, `RCTF_TEAM_TOKEN`, ...), and
generic `CTFX_<KEY>` names are used as fallbacks. A non-empty environment
variable overrides the file. When a profile's name is not a platform name, set
`CTFX_PLATFORM=<platform>` in the file.

Existing ocws workspaces keep working: `.opencode/ctf/<platform>.env` is read
if there is no `.ctfx/` directory. `ctfx config migrate` copies those files
across.

| Platform | Keys |
|----------|------|
| `ctfd` | `CTFD_URL`, `CTFD_TOKEN` or `CTFD_SESSION_COOKIE` (+ `CTFD_CSRF_TOKEN`), `CTFD_AUTH_MODE`, `CTFD_INSTANCE` (kubectf/whale/owl/chall-manager), `CTFD_VERIFY_SSL` |
| `rctf` | `RCTF_URL`, exactly one of `RCTF_AUTH_TOKEN` / `RCTF_TEAM_TOKEN`, `RCTF_VERIFY_SSL` |
| `gzctf` | `GZCTF_URL` (or a `/games/<id>` URL), `GZCTF_GAME`, `GZCTF_TOKEN` or `GZCTF_USERNAME`+`GZCTF_PASSWORD` |
| `htb` | `HTB_URL` (default `https://ctf.hackthebox.com`), `HTB_EVENT`, `HTB_TOKEN` (JWT) |

### Getting past bot screening

Some platforms sit behind Cloudflare or a WAF. Set `CTFX_IMPERSONATE=chrome`
(or `firefox`/`safari`) to send a real browser's TLS + HTTP/2 + header
fingerprint. That defeats passive screening; for a JavaScript challenge
(Turnstile) copy a `cf_clearance` cookie from your browser into `CTFX_COOKIES`
with a matching `CTFX_USER_AGENT`. All three also work per-platform
(`CTFD_IMPERSONATE`, ...). ctfx reports a clear error when it hits a challenge page.

## Agent permissions

Allow the read commands and require approval for the write commands. OpenCode
example (later rules win):

```json
"permission": { "bash": {
  "ctfx *": "ask",
  "ctfx chal *": "allow", "ctfx hint ls *": "allow", "ctfx solves*": "allow",
  "ctfx scoreboard*": "allow", "ctfx team*": "allow", "ctfx caps*": "allow",
  "ctfx instance status *": "allow", "ctfx config show*": "allow"
} }
```

## Plugins

To add a platform, put an executable named `ctfx-driver-<name>` on `PATH` or
in `.ctfx/drivers/`. It receives one JSON request on stdin and writes one JSON
response to stdout. See [docs/plugins.md](docs/plugins.md) and the ~50-line
Python example in [examples/drivers](examples/drivers/ctfx-driver-example).

## Go API

`pkg/ctf` exports the normalized types and the `Driver` interface.
