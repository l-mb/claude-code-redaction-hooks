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

To allow the filter list to be safely committed alongside the source code, secrets can be hashed with SHA-256.

A regex configured via `hash_extractor` extracts candidate segments from input, hashes each, and compares against the rule's `pattern` to decide block/redact.

```bash
echo "SecretProjectName" | redact secret add --id project-name
```

## 0.2.0 release notes

- **Behaviour fix**: PreToolUse and PostToolUse hooks no longer ship with a hard-coded tool matcher. Earlier versions installed `matcher: "Write|Edit|Bash"` (PreToolUse) and `matcher: "Read|Bash|Grep|Glob|WebFetch"` (PostToolUse), which silently bypassed `Read`, `MultiEdit`, `WebSearch`, `Task`/Agent, and MCP `mcp__*__*` tools. Rules with `tool: Read` or `file_tools: read` now fire as the README has always documented. Re-run `redact claude-setup` (or `--uninstall && claude-setup`) to refresh existing installs.
- **New hook events**: `PostToolUseFailure`, `PostCompact`, `Stop`, `SubagentStop`, and `InstructionsLoaded` are scanned (warn-only — see Limitations). They detect leaks in failed-tool errors, post-compaction summaries, the last assistant message, and loaded `CLAUDE.md` / `.claude/rules/*.md` files.
- **Spilled tool output**: when Claude Code persists a tool result >50K chars to disk, the redaction hook now reads the spill file and applies block rules; redact rules surface a `redact-skipped` audit entry rather than silently passing.
- **`additionalContext`** is now sent on `PreToolUse` redacts and `UserPromptSubmit` redacts so the model knows a rule fired (rule IDs only, never matched text).
- **`tool_use_id`** is recorded in audit entries for pre/post correlation.
- **`$CLAUDE_PROJECT_DIR`** is honoured by `redact hook` when set, anchoring rules and audit log to the project root regardless of the hook process's cwd.
