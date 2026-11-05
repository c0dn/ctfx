# ctfx data contract and exec driver protocol (v2)

This is the one contract every ctfx driver meets, built-in or exec plugin. The
Go types are in [`pkg/ctf`](../pkg/ctf/ctf.go); this page is the field-level
reference. There is a single protocol version, 2: ctfx refuses a driver that
does not declare it.

Every result a driver returns is checked against this contract
(`ctf.Checked`). A result that breaks it (an unknown state, a running instance
with no address, a non-RFC 3339 time) is reported as a `remote` error naming
the operation, never passed on as data.

## Exec plugins

An exec driver is any executable named `ctfx-driver-<name>`. ctfx searches for
it in this order:

1. `<workspace>/.ctfx/drivers/ctfx-driver-<name>` (the bare name `<name>` also works here)
2. `PATH`

A driver with the same name as a built-in driver is ignored. A profile selects
the driver with `CTFX_PLATFORM=<name>`, or by naming the profile file
`.ctfx/<name>.env`.

### Call

For every operation, ctfx runs `ctfx-driver-<name> <op>` with the workspace
root as its working directory and writes one JSON request to its stdin:

```json
{
  "protocol": 2,
  "op": "submit",
  "config": {
    "platform": "example",
    "profile": "example",
    "root": "/path/to/workspace",
    "source": "/path/to/workspace/.ctfx/example.env",
    "values": { "EXAMPLE_URL": "https://ctf.example", "EXAMPLE_TOKEN": "..." }
  },
  "args": { "id": "12", "flag": "flag{...}" }
}
```

- `values` holds every key from the profile file, plus environment variables
  that start with `<NAME>_` or `CTFX_`. Credentials stay in the profile file;
  the driver needs no config loader of its own.
- The driver's environment is ctfx's. Proxies come in as the usual
  `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`; honour them (Python's urllib does
  by default through `ProxyHandler(getproxies())`).
- One process runs per call, so calls may run concurrently. A driver that keeps
  state between calls (a session cookie, an instancer handle) stores it under
  `<root>/.ctfx/state/`, mode 0600.

### Timeout

Each call has a deadline: 60 s, or `CTFX_TIMEOUT` seconds from the profile.
A driver that runs past it is killed and the call fails with kind `timeout`
(exit code 7). Put your own shorter timeouts on platform requests so you can
report a precise error first.

### Reply

The driver writes exactly one JSON object to stdout:

```json
{"result": <op result>}
```

or, on failure:

```json
{"error": {"kind": "auth", "message": "token rejected"}}
```

stderr is free for logs; ctfx shows it only when stdout is not valid JSON.

## Error kinds

| kind | meaning | exit code |
|------|---------|-----------|
| `usage` | bad arguments (unknown action, empty ID) | 2 |
| `config` | the profile is missing or wrong; also a protocol mismatch | 3 |
| `auth` | the credentials are wrong or not allowed | 3 |
| `expired` | credentials that worked before have expired: refresh the cookie or token (for example by signing in again in a browser) | 6 |
| `unsupported` | the platform cannot do this | 4 |
| `not_found` | no such challenge, hint or file | 5 |
| `timeout` | the platform or driver did not answer in time | 7 |
| `remote` | anything else the platform got wrong | 5 |

An unrecognised kind is treated as `remote`. Use `expired`, not `auth`, when
you can tell a session went stale (a login redirect, an "expired" message, a
401 on a token that worked earlier): a caller can then refresh instead of
asking for new credentials.

A wrong flag is not an error: `submit` returns a result with status
`incorrect` and exit code 0.

## Operations

| op | args | result |
|----|------|--------|
| `capabilities` | - | [Capabilities](#capabilities), with `"protocol": 2` |
| `list_challenges` | - | `[Challenge]` |
| `get_challenge` | `id` | `Challenge` |
| `submit` | `id`, `flag` | `SubmitResult` |
| `solves` | - | `[Solve]` |
| `scoreboard` | `limit`, `offset`, `division` | `{"total", "entries": [ScoreEntry]}` |
| `team` | - | `{"user": Account, "team": Account, "team_error"}` |
| `prepare_download` | `url` | `{"url", "headers": {...}}`; ctfx performs the download |
| `hints` | `challenge_id` | `[Hint]` |
| `unlock_hint` | `hint_id` | `Hint` |
| `instance` | `action`, `challenge` | `Instance` |

ctfx calls an operation only if `capabilities` advertised it; otherwise it
exits with code 4 without starting the driver. Challenge IDs are strings. If
`get_challenge` fails with `not_found` or `usage`, or `submit` returns
`bad_challenge`, ctfx looks the argument up as a challenge name via
`list_challenges` and retries with the matching ID.

## Types

Optional fields may be omitted or `null`. Times are always RFC 3339 in UTC
(`2026-10-23T14:31:40Z`); convert the platform's format in the driver
(`ctf.Timestamp` does this for Go drivers).

### Capabilities

| field | type | meaning |
|-------|------|---------|
| `protocol` | int | must be `2` (exec plugins only) |
| `challenges`, `submit`, `solves`, `scoreboard`, `team`, `download`, `hints`, `unlock_hint`, `instances` | bool | which operations exist |
| `instance_actions` | [string] | instance actions besides `status`: any of `start`, `extend`, `stop`, `reset` |
| `max_instances` | int | instances the team may run at once; `0` = unknown |

`status` is implied by `instances: true`. If a driver lists `start` and `stop`
but not `reset`, ctfx implements `reset` as stop then start. An action that is
not listed exits with code 4.

### Challenge

| field | type | meaning |
|-------|------|---------|
| `id` | string | **required**; the platform's ID |
| `name` | string | **required** |
| `category` | string | |
| `author` | string | optional |
| `points` | number or null | current value; null when hidden |
| `solved` | bool | solved by **our** team |
| `solves` | int or null | solve count across teams |
| `description` | string | full text (markdown or HTML as the platform gives it); may be empty in `list_challenges` |
| `connection` | [Connect](#connect) or null | the static target the challenge names (`nc host port`, a URL). Not a per-team instance: that is `instance` |
| `files` | [[File](#file)] | |
| `hints` | [[Hint](#hint)] | as far as `get_challenge` knows them |
| `instance` | [InstanceRef](#instanceref) or null | set when the challenge uses per-team instances |
| `limits` | [ChallengeLimits](#challengelimits) or null | the platform's own limits, when it states them |
| `extra` | object | platform-specific fields with **no shared meaning**. Consumers must not depend on it; anything with a shared meaning gets a real field |

Parse connection text with `ctf.ParseConnect` (Go) or emit the object
directly. A challenge whose description only names a target in prose should
still get `connection` when the target is unambiguous.

### ChallengeLimits

| field | type | meaning |
|-------|------|---------|
| `max_attempts` | int | total submissions allowed; omit when unlimited |
| `remaining_attempts` | int | submissions our team has left |
| `deadline` | string | when the challenge stops accepting flags (RFC 3339) |

### File

| field | type | meaning |
|-------|------|---------|
| `name` | string | file name to save as |
| `url` | string | absolute URL; ctfx calls `prepare_download` for auth headers |

### Hint

| field | type | meaning |
|-------|------|---------|
| `id` | string | **required**; what `unlock_hint` takes |
| `title` | string | optional |
| `cost` | number | points spent to unlock; `0` = free |
| `locked` | bool | |
| `content` | string or null | null while locked; **required** when unlocked |

### InstanceRef

| field | type | meaning |
|-------|------|---------|
| `backend` | string | the instancer kind (`kubectf`, `whale`, `rctf`, `gzctf`, ...) |
| `slug` | string | what `instance` takes as `challenge` (often the ID) |
| `lifetime_seconds` | int | how long a fresh instance lives, when known |

### Instance

The state of the team's instance **after** the action.

| field | type | meaning |
|-------|------|---------|
| `challenge` | string | |
| `backend` | string | |
| `action` | string | `status`, `start`, `extend`, `stop` or `reset` |
| `state` | string | one of the states below |
| `connect` | [Connect](#connect) | **required** when `state` is `running` |
| `expires` | string | when it stops on its own (RFC 3339), when known |
| `owner` | string | the account that owns it, when the platform says |
| `retry_after_seconds` | int | with `busy`: wait this long |
| `message` | string | the platform's words, for people |
| `http_status` | int | the platform's HTTP status, for debugging |

States:

| state | meaning | what a caller does |
|-------|---------|--------------------|
| `running` | up and reachable at `connect` | connect |
| `pending` | being created, reset or stopped | poll `status` |
| `stopped` | no instance (never started, stopped, or expired) | `start` if needed |
| `busy` | the instancer refused for capacity or a rate limit | wait `retry_after_seconds`, then retry |
| `unknown` | the platform cannot tell (e.g. no session to ask with) | `start` (most instancers attach to an existing one) |
| `error` | the platform reported a failure | read `message` |

A start the platform accepted but that has no address yet is `pending`, not
`running`. Starting a running instance returns it (`running`), not an error.

### Connect

| field | type | meaning |
|-------|------|---------|
| `host` | string | `host` or `host:port` |
| `port` | int | the port, when known |
| `url` | string | for web and WebSocket targets |
| `tls` | bool | the target speaks TLS |
| `command` | string | a ready-to-run client line (`nc host port`, `openssl s_client ...`, `wsrx connect ...`) |

At least one of `host` and `url` is set.

### SubmitResult

| field | type | meaning |
|-------|------|---------|
| `challenge_id` | string | |
| `status` | string | one of the statuses below |
| `correct` | bool | `true` exactly when `status` is `correct` |
| `message` | string | the platform's words |
| `retry_after_seconds` | int | with `rate_limited`: wait this long (from `Retry-After` or the body) |
| `http_status`, `response_kind` | | for debugging |

Statuses: `correct`, `incorrect`, `already_solved`, `rate_limited`,
`bad_challenge` (no such challenge), `not_started`, `ended`, `error` (the
platform answered but the verdict is unclear: never assume the flag was
wrong).

### Solve, ScoreEntry, Account, Member

As in `pkg/ctf`: `Solve` is `{challenge_id, name, category, points, date}`;
`ScoreEntry` is `{position, account_id, account_type, name, score, extra}`;
`Account` is `{id, name, email, score, place, members, extra}`.

## Writing a driver

Start from [`examples/drivers/ctfx-driver-example`](../examples/drivers/ctfx-driver-example):
a Python driver with a board, hints, limits and a full instance lifecycle that
passes the contract checks. Test it from a workspace:

```sh
mkdir -p .ctfx/drivers && cp ctfx-driver-mysite .ctfx/drivers/
printf 'CTFX_PLATFORM=mysite\nMYSITE_URL=https://ctf.example\n' > .ctfx/mysite.env
ctfx caps                      # handshake: protocol and capabilities
ctfx chal ls && ctfx chal show <id>
ctfx instance status <id> && ctfx instance start <id>
```

Any contract violation shows up as a `remote` error naming the operation and
the field.
