# Exec driver protocol (v1)

An exec driver is any executable named `ctfx-driver-<name>`. ctfx searches for
it in this order:

1. `<workspace>/.ctfx/drivers/ctfx-driver-<name>` (the bare name `<name>` also works here)
2. `PATH`

A driver with the same name as a built-in driver is ignored.

A profile selects the driver with `CTFX_PLATFORM=<name>`, or by naming the
profile file `.ctfx/<name>.env`.

## Call

For every operation, ctfx runs `ctfx-driver-<name> <op>` with the workspace
root as its working directory and writes one JSON request to its stdin:

```json
{
  "protocol": 1,
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

`values` contains every key from the profile file, plus environment variables
that start with `<NAME>_` or `CTFX_`. Credentials therefore stay in the
profile file; the driver does not need its own config loader.

## Reply

The driver writes exactly one JSON object to stdout:

```json
{"result": <op result>}
```

or, on failure:

```json
{"error": {"kind": "auth", "message": "token rejected"}}
```

Error kinds and the ctfx exit codes they map to:

| kind | exit code |
|------|-----------|
| `usage` | 2 |
| `config`, `auth` | 3 |
| `unsupported` | 4 |
| `not_found`, `remote` | 5 |

An unrecognised kind is treated as `remote`. If the driver produces no valid
JSON on stdout, ctfx reports a remote error and includes the driver's stderr.

## Operations

Results use the JSON shape of the matching type in `pkg/ctf`.

| op | args | result |
|----|------|--------|
| `capabilities` | - | `{"challenges","submit","solves","scoreboard","team","download","hints","unlock_hint","instances"}` booleans |
| `list_challenges` | - | `[Challenge]` |
| `get_challenge` | `id` | `Challenge` |
| `submit` | `id`, `flag` | `SubmitResult` (`status` must be one of the shared statuses) |
| `solves` | - | `[Solve]` |
| `scoreboard` | `limit`, `offset`, `division` | `{"total", "entries": [ScoreEntry]}` |
| `team` | - | `{"user": Account, "team": Account, "team_error"}` |
| `prepare_download` | `url` | `{"url", "headers": {...}}`; ctfx performs the download |
| `hints` | `challenge_id` | `[Hint]` |
| `unlock_hint` | `hint_id` | `Hint` |
| `instance` | `action` (`status`/`start`/`extend`/`stop`), `challenge` | `Instance` |

ctfx calls an operation only if `capabilities` advertised it. Otherwise it
exits with code 4 without starting the driver. Challenge IDs are strings.
If `get_challenge` fails with `not_found` or `usage`, or `submit` returns
`bad_challenge`, ctfx looks up the argument as a challenge name via
`list_challenges` and retries with the matching ID.

The shared submit statuses are `correct`, `incorrect`, `already_solved`,
`rate_limited`, `bad_challenge`, `not_started`, `ended`, and `error`.
