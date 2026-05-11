# WARNING

Due to limitations in Claude Code, the hook mechanism is very fragile. The documentation does not match the actual behaviour. Behaviour is inconsistent between hooks. Hooks change behaviour between versions with no real release note entry. The model will try to work around operations that hooks deny.

Since Claude Code is proprietary, the actual behaviour can't easily be checked, and the model will occasionally assume capturing `claude`'s actual behaviour (to capture the actual JSON given to hooks) constitutes a forbidden reverse engineering attempt; I assume no responsibility for your subscription getting locked.

Not all behaviour in Claude Code can be hooked into.

At best, it will help you get notified that something leaked.

**DO NOT** rely on this tool to actually offer meaningful protection.

Keep *any* agent harness, but especially **this** harness, far away from access to any unsanitized information you'd not also happily upload to a public Internet archive.

This has been an enlightening experiment for me about where we are at with `claude`. But some experimental results serve as warnings.

# Claude Code Redaction Hooks

Hooks for Claude Code to block or redact secrets/PII before LLM submission or tool execution, redact tool output before it returns, and warn on matches in transcripts (compaction, stop, subagent stop), failed tool calls, and loaded memory files.

Redaction is consistent (tracked via a mapping file). Reversing is not currently possible, see `Limitations`.

## Limitations

What each hook event can do is determined by Claude Code:

- **block** — refuse the action: PreToolUse stops the tool from running; PostToolUse hides the result from the model; UserPromptSubmit drops the prompt; PreCompact aborts the compaction. Always paired with a `block` audit entry.
- **redact** — rewrite the payload in place: PreToolUse swaps secrets in the tool input before it executes; PostToolUse swaps secrets in `tool_response` before the model sees it. The mapping file makes the same secret get the same replacement across calls.
- **observe** — scan and audit only. The hook cannot stop or rewrite anything because Claude Code provides no decision channel for that event; matches are written to the audit log and stderr so an operator can react after the fact. Rules with `action: redact` on observe-only events surface as `redact-skipped` in the audit and a stderr warning.

| Hook                  | block | redact                          | observe |
|-----------------------|-------|---------------------------------|---------|
| PreToolUse            | Y     | Y (tool input rewritten)        | Y       |
| PostToolUse           | Y     | Y (tool output rewritten)       | Y       |
| PostToolUseFailure    | N     | N                               | Y       |
| PostToolBatch         | Y     | N — `redact-skipped` audit      | Y       |
| UserPromptSubmit      | Y     | N — warns + `additionalContext` | Y       |
| UserPromptExpansion   | Y     | N — warns + `additionalContext` | Y       |
| PreCompact            | Y     | N — warns only (no rewrite)     | Y       |
| PostCompact           | N     | N                               | Y       |
| InstructionsLoaded    | N     | N                               | Y       |
| Stop / SubagentStop   | (N)   | N                               | Y       |

`PostToolBatch` fires after a parallel tool batch resolves; per-entry `tool_response` outputs have already been shipped to context, so `redact`-action matches surface as a `redact-skipped` audit entry rather than rewriting in place. `UserPromptExpansion` covers the `/skillname args` slash-command path that bypasses both `UserPromptSubmit` and `PreToolUse`; CC docs do not provide an `updatedInput` channel, so redact-action matches use the same `additionalContext` warning as `UserPromptSubmit`.

Stop/SubagentStop *can* return `decision:"block"`, but doing so just forces Claude to keep talking; it does not unsend the message that already leaked. We treat them as observe-only.

### What block/redact actually prevents from leaving the machine

The table above lists which *action* each hook supports. Supporting `block` does not by itself mean blocking keeps data on the local machine — for some events, the data has already left by the time the hook fires.

Two remote endpoints can leak: the **LLM API** (Anthropic uploads every prompt, tool result, and compaction summary), and a **tool's own outbound network calls** (`WebFetch`, `WebSearch`, MCP servers, `Bash` running `curl`/`ssh`/`gh`/etc.). A hook can only prevent egress on a channel it sits in front of.

| Hook                  | Stops the tool's network call         | Stops upload to the LLM                              |
|-----------------------|---------------------------------------|------------------------------------------------------|
| PreToolUse            | block, redact (input rewritten)       | block (no result produced), redact                   |
| PostToolUse           | — tool already ran                    | block (result hidden), redact (response rewritten)   |
| PostToolUseFailure    | — tool already ran                    | — observe-only                                       |
| PostToolBatch         | — tool already ran                    | — outputs already shipped to context                 |
| UserPromptSubmit      | n/a                                   | block; redact warns only                             |
| UserPromptExpansion   | n/a                                   | block; redact warns only                             |
| PreCompact            | n/a                                   | block (summary request aborted); redact warns only   |
| PostCompact           | n/a                                   | — round-trip already complete                        |
| InstructionsLoaded    | n/a                                   | — no decision channel; file queued for next turn     |
| Stop / SubagentStop   | n/a                                   | — final message already sent                         |

In short:

- **`PreToolUse` is the only hook that can stop a tool from reaching the network.** If a tool's first action would leak (e.g. `curl` with a secret in the URL, an MCP call carrying customer data), only `PreToolUse` can prevent it.
- For the **LLM upload channel**, the effective prevention points are `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `UserPromptExpansion`, and `PreCompact`. On the redact side, `UserPromptSubmit` / `UserPromptExpansion` / `PreCompact` warn only — Claude Code provides no rewrite channel for those events.
- `PostToolUseFailure`, `PostToolBatch`, `PostCompact`, `InstructionsLoaded`, `Stop`, and `SubagentStop` are **audit-only with respect to egress**: by the time they fire, the matched payload has already shipped (or will ship without us being able to intervene). Their value is post-hoc alerting, not prevention.

### `@`-mention expansion bypasses every hook

When a user types `@filename` in a prompt, Claude Code reads the file and inlines its contents into the model context **outside the hook pipeline**. Verified empirically on CC 2.1.138 via the `atmention-file` scenario in `redact verify-cc-schema`: the file body never appears in any inbound payload — not `UserPromptSubmit.prompt` (which carries only the literal `@filename` token), not a synthetic `PreToolUse` / `PostToolUse:Read`, not `UserPromptExpansion`, not `InstructionsLoaded`. The hook only sees the content post-hoc in `Stop.last_assistant_message` if the model echoes it back. By then the leak has already happened.

Mitigation: scan for the literal `@<path>` token at `UserPromptSubmit` and block, forcing the user to issue an explicit `Read` tool call (which `PreToolUse` / `PostToolUse` *can* intercept and rewrite):

```yaml
- id: refuse-at-mention
  pattern: '@[\w./-]+\.\w+'
  action: block
  target: llm
  description: '@-mention expansions bypass hooks; require explicit Read tool use.'
```

### Session halt on block

Hook events that support a halt path (`PreToolUse`, `PostToolBatch`, `UserPromptSubmit`, `UserPromptExpansion`, `PreCompact`) emit `continue: false` + `stopReason` alongside their deny/block decision. CC honours this by halting subsequent turns rather than letting the model retry. `PostToolUse` intentionally stays on the exit-2 path: the tool has already executed by the time it fires, so halting only delays the next turn — it cannot un-ship the leaked content.

> **Caveat — parallel tool batches.** Within a single parallel tool batch, every call's `PreToolUse` still fires (and is individually denied via `permissionDecision: deny`) before the halt takes effect on the *next* batch. No leak fires — every call in the batch is blocked — but the halt is not instantaneous within a batch. Verified empirically on CC 2.1.138.

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

## Release notes

See [CHANGELOG.md](CHANGELOG.md) for per-version release notes.
