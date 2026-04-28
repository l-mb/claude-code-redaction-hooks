# Claude Code Redaction Hooks

Hooks for Claude Code to block or redact secrets/PII before LLM submission or tool execution, redact tool output before it returns, and warn on matches in transcripts about to be compacted.

Redaction is consistent (tracked via a mapping file). Reversing is not currently possible, see `Limitations`.

## Limitations

Due to limitations in Claude Code's hook mechanism:

| Hook              | block | redact                       |
|-------------------|-------|------------------------------|
| PreToolUse        | Y     | Y (tool input modified)      |
| PostToolUse       | Y     | Y (tool output modified)     |
| UserPromptSubmit  | Y     | N — warns only               |
| PreCompact        | Y     | N — warns only (no rewrite)  |

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
