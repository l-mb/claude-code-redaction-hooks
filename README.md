# Claude Code Redaction Hooks

Hooks for Claude Code to block or redact secrets/PII before LLM submission or tool execution, redact tool output before it returns, and warn on matches in transcripts (compaction, stop, subagent stop), failed tool calls, and loaded memory files.

Redaction is consistent (tracked via a mapping file). Reversing is not currently possible, see `Limitations`.

## Limitations

What each hook event can do is determined by Claude Code:

- **block** — refuse the action: PreToolUse stops the tool from running; PostToolUse hides the result from the model; UserPromptSubmit drops the prompt; PreCompact aborts the compaction. Always paired with a `block` audit entry.
- **redact** — rewrite the payload in place: PreToolUse swaps secrets in the tool input before it executes; PostToolUse swaps secrets in `tool_response` before the model sees it. The mapping file makes the same secret get the same replacement across calls.
- **observe** — scan and audit only. The hook cannot stop or rewrite anything because Claude Code provides no decision channel for that event; matches are written to the audit log and stderr so an operator can react after the fact. Rules with `action: redact` on observe-only events surface as `redact-skipped` in the audit and a stderr warning.

| Hook                | block | redact                          | observe |
|---------------------|-------|---------------------------------|---------|
| PreToolUse          | Y     | Y (tool input rewritten)        | Y       |
| PostToolUse         | Y     | Y (tool output rewritten)       | Y       |
| PostToolUseFailure  | N     | N                               | Y       |
| UserPromptSubmit    | Y     | N — warns + `additionalContext` | Y       |
| PreCompact          | Y     | N — warns only (no rewrite)     | Y       |
| PostCompact         | N     | N                               | Y       |
| InstructionsLoaded  | N     | N                               | Y       |
| Stop / SubagentStop | (N)   | N                               | Y       |

Stop/SubagentStop *can* return `decision:"block"`, but doing so just forces Claude to keep talking; it does not unsend the message that already leaked. We treat them as observe-only.

Tool output that Claude Code spills to disk (>50K chars) is scanned via the `file_path` referenced in the spill stub. Matches against `block` rules still block; `redact` matches surface as a `redact-skipped` audit entry — the spill file is not rewritten because there's no contract that Claude Code re-reads it after the hook returns.

No reversible redaction (un-redacting responses not implemented).

## Install

```bash
# User-wide install (recommended)
uv tool install --reinstall .
redact claude-setup           # configure hooks in .claude/settings.json (idempotent merge)

# Or development install (venv only)
uv pip install -e .
```

`claude-setup` merges into existing `.claude/settings.json`; it never overwrites unrelated entries.

```bash
redact claude-setup --dry-run     # print resulting settings.json without writing
redact claude-setup --uninstall   # remove only the redact-hook entries
redact claude-setup --global      # write to ~/.claude/settings.json
```

## Usage

```bash
redact secret add --id NAME    # add hashed secret (reads from stdin or $REDACT_SECRET)
                               # optional: --action {block,redact,warn} (default block)
                               #           --target {llm,tool,both}     (default both)
                               #           --hash-extractor REGEX        (default \b\w{4,}\b)
                               #           --replacement STR             (only with --action redact)
redact secret list             # list hashed rule ids
redact edit                    # edit rules in $EDITOR (validates after save)
redact validate                # validate rules file syntax
redact check FILE...           # scan files against rules
redact check --rules FILE      # use custom rules file
redact check -q                # quiet mode (only output blocked)
redact audit tail [-n N]       # last N audit entries (default 20)
redact audit since DURATION    # entries newer than e.g. 30m, 1h, 7d
redact audit prune --before D  # delete entries older than DURATION (e.g. 30d)
redact hook                    # run as Claude Code hook (reads JSON from stdin)
```

Add `--global` to any command to use `~/.claude/.redaction_rules` instead of project.

### Audit log

Each block/redact/warn outcome is appended to a JSONL audit log:

- Project: `.claude/redaction_audit.log`
- Global: `~/.claude/redaction_audit.log`

Use `redact audit tail` / `redact audit since` to inspect recent activity.

### Mapping file

Consistent redaction replacements are stored in:

- Project: `.claude/redaction_mappings.json`
- Global: `~/.claude/redaction_mappings/global.json`

## Configuration

Create `.redaction_rules` (YAML, see `.redaction_rules.example` for more):

```yaml
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block              # or: redact, warn
    description: AWS Access Key

  - id: email
    pattern: '[a-z]+@corp\.com'
    action: redact
    replacement: email         # or: ip, hostname, or literal string
    target: tool               # or: llm, both (default)

  # Block dangerous git flags (Bash only)
  - id: no-verify
    pattern: '--no-verify'
    action: block
    tool: Bash                 # only applies to Bash commands
    description: Bypasses pre-commit hooks

  # Path-based rules (match the file/path the tool touches)
  - id: block-env-read
    path_pattern: '*.env'
    action: block
    tool: Read

  # File-content rules (scan first 100 lines of the target file)
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    file_tools: read           # or: write, rw
    action: block
```

> **Note on hand-edited rules.** `redact secret add` (and any other CLI
> write path) re-serialises the rules file with `yaml.dump`, which **drops
> comments and may reflow quoting**. If you maintain `.redaction_rules` by
> hand with comments or anchors, edit it directly with `redact edit` and
> avoid mixing `secret add` into the same file — or restore your curated
> copy from version control afterwards.

### Rule fields

- `id`: rule identifier (required)
- `pattern`: regex (default) or fixed string when `is_regex: false`
- `path_pattern`: glob matched against the path the tool touches
- `file_content_pattern`: regex matched against the target file's existing contents
- `file_tools`: which file operations the content rule applies to — `read`, `write`, or `rw`
- `hashed`: if true, `pattern` is a SHA-256 hash compared against extracted segments
- `hash_extractor`: regex extracting segments to hash
- `action`: `block`, `redact`, or `warn`
- `replacement`: for `redact` — literal string, or `ip` / `email` / `hostname`
- `target`: `llm`, `tool`, or `both` (default)
- `tool`: filter to a specific tool name (e.g. `Bash`, `Write`); omit for all tools

### Hashed secrets

Secrets can be hashed with SHA-256 so the rules file is less revealing if it leaks.

A regex configured via `hash_extractor` extracts candidate segments from input, hashes each, and compares against the rule's `pattern` to decide block/redact.

```bash
echo "SecretProjectName" | redact secret add --id project-name
```

> **Threat model.** SHA-256 hashing protects the rules file from casual
> inspection only. With the default `hash_extractor: \b\w{4,}\b` an
> attacker with the rules file can hash every dictionary word and try
> common passphrases offline — a short codename, an English passphrase,
> or a personal name will not survive the brute force. Hashed rules are
> appropriate for one of:
>
> - **strong secrets with significant entropy** (random tokens, generated
>   API keys), where exhaustive search is infeasible; or
> - **secrets that shouldn't be committed to the repo at all** — keep
>   those in a `--global` rules file under `~/.claude/`, or load them at
>   runtime from a vault.
>
> Choosing a tighter `hash_extractor` (e.g. `\b[A-Za-z0-9_-]{16,}\b`)
> raises the bar somewhat by limiting what segments the matcher even
> tries to hash, but it does not change the underlying offline-search
> threat for low-entropy inputs.

## Verifying CC compatibility

Claude Code's hook payload schema is undocumented in detail and drifts between releases. Two defenses ship in-tree:

- **Runtime drift signal.** Every handler audits a `schema-drift` entry (and writes one stderr line) when (a) a match was caught only by the recursive backstop instead of the per-tool extractor, or (b) a required top-level input key (e.g. `transcript_path`, `file_path`, `error`) is missing from the payload. Operators surface them with `redact audit since 7d | jq 'select(.action=="schema-drift")'`.
- **Live verification harness.** `redact verify-cc-schema` invokes `claude -p` headlessly through scripted scenarios (Bash success, Bash failure, Read, Grep, subagent), captures every hook payload via `REDACT_HOOK_DUMP_DIR`, runs the extractors against each, and diffs the top-level keys against the committed corpus in `tests/fixtures/cc-payloads/`.

```bash
redact verify-cc-schema --report-dir ./tmp/verify-out
# → verify-out/report.json  (machine-parseable; feed back to Claude for analysis)
# → verify-out/report.md    (human summary; "Drift detected" section if any)
# Exit 0 = no drift, 1 = drift detected, 2 = harness error (e.g. claude not on PATH).
```

If the report flags drift you can either:

- File an upstream bug or wait for confirmation, OR
- Update the corpus + extractor: `redact verify-cc-schema --update-golden` regenerates `tests/fixtures/cc-payloads/*.json` from the live captures (anonymised). Review the diff, update `_iter_output_fields` / `_get_tool_input_*` in `src/redaction_hooks/hooks.py` if a field name moved, then run `uv run pytest tests/test_extractor_fixtures.py` to confirm extractors recognise the new shape.

The harness needs `claude` on `PATH` and a working CC API session. Default scenarios use ~5 short turns; expect the run to consume modest API quota each time.

For ad-hoc payload inspection without the full harness: `REDACT_HOOK_DUMP_DIR=/tmp/cc-dump` causes `redact hook` to dump the raw stdin payload before processing it, so any installed CC session populates the directory automatically.

## 0.3.0 release notes

- **Behaviour fix**: every handler that detects a `redact`-action match but
  cannot rewrite the payload now audits as `redact-skipped` (matching the
  README contract). Affects `UserPromptSubmit`, `PostToolUse` (non-dict /
  no-change branches), `PostToolUseFailure`, `PreCompact`, `PostCompact`,
  `InstructionsLoaded`, `Stop`, `SubagentStop`. The `PostToolUse` success
  path that produces a real `updatedToolOutput` still audits as `redact`.
  Operator queries against `redact audit since 7d | jq 'select(.action=="redact")'`
  now reliably reflect "rewrite happened" rather than "rule matched somewhere".
- **Security fix**: `path_pattern` rules for `Bash` now see paths inside
  `bash -c "<inner>"` / `sh -c '<inner>'` / `dash`/`zsh`/`ksh` wrappers
  (incl. `env VAR=x bash -c …` and `-c=<inner>` forms). Previously the
  inner command landed as a single shlex token and silently bypassed the
  matcher.
- **CLI**: `redact secret add` now exposes `--action {block,redact,warn}`,
  `--target {llm,tool,both}`, `--hash-extractor REGEX`, and `--replacement
  STR`. Hashed redact-style rules no longer require hand-editing.
- **CLI**: `redact hook` defaults to `Path.cwd()` when `$CLAUDE_PROJECT_DIR`
  is unset (previously fell back to the user-global audit log, which
  `redact audit tail` doesn't read by default). Manual hook invocations
  from a project shell now show up in `redact audit tail` as expected.
- **Docs**: README documents the threat model for hashed rules
  (brute-forceable for low-entropy inputs) and warns that `redact secret
  add` re-serialises the rules file via `yaml.dump` (drops comments).
- **Internal**: `hooks.py` (1530 lines) split into a `handlers/` package
  plus `extractors.py` and `drift.py`. `handle_pre_tool_use` (was CCN 59)
  and `iter_output_fields` (was CCN 42) are decomposed; no behaviour
  change. Test imports updated; the public API reachable via
  `redaction_hooks.run_hook` is unchanged.
- `__version__` is now sourced from `importlib.metadata` so `pyproject.toml`
  is the single source of truth.

## 0.2.0 release notes

- **Behaviour fix**: PreToolUse and PostToolUse hooks no longer ship with a hard-coded tool matcher. Earlier versions installed `matcher: "Write|Edit|Bash"` (PreToolUse) and `matcher: "Read|Bash|Grep|Glob|WebFetch"` (PostToolUse), which silently bypassed `Read`, `MultiEdit`, `WebSearch`, `Task`/Agent, and MCP `mcp__*__*` tools. Rules with `tool: Read` or `file_tools: read` now fire as the README has always documented. Re-run `redact claude-setup` (or `--uninstall && claude-setup`) to refresh existing installs.
- **New hook events**: `PostToolUseFailure`, `PostCompact`, `Stop`, `SubagentStop`, and `InstructionsLoaded` are scanned (warn-only — see Limitations). They detect leaks in failed-tool errors, post-compaction summaries, the last assistant message, and loaded `CLAUDE.md` / `.claude/rules/*.md` files.
- **Spilled tool output**: when Claude Code persists a tool result >50K chars to disk, the redaction hook now reads the spill file and applies block rules; redact rules surface a `redact-skipped` audit entry rather than silently passing.
- **`additionalContext`** is now sent on `PreToolUse` redacts and `UserPromptSubmit` redacts so the model knows a rule fired (rule IDs only, never matched text).
- **`tool_use_id`** is recorded in audit entries for pre/post correlation.
- **`$CLAUDE_PROJECT_DIR`** is honoured by `redact hook` when set, anchoring rules and audit log to the project root regardless of the hook process's cwd.
