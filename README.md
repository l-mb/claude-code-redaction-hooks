# Claude Code Redaction Hooks

Hooks for Claude Code to block or redact secrets/PII before LLM submission or tool execution.

Redaction is consistent (tracked via a mapping file). Reversing is not currently possible, see `Limitations`.

## Limitations

Due to limitations in Claude Code's hook mechanism, for now:

- `redact` action only fully works for `target: tool` (`PreToolUse` supports `updatedInput`)
- `redact` with `target: llm` warns and allows (`UserPromptSubmit` cannot modify prompts)
- No reversible redaction (un-redacting responses not implemented, cannot modify responses via hooks)

## Install

```bash
# User-wide install (recommended)
uv tool install --reinstall .
redact claude-setup        # configure hooks in .claude/settings.json

# Or development install (venv only)
uv pip install -e .
```

## Usage

```bash
redact secret add --id NAME   # add hashed secret (reads from stdin)
redact edit                   # edit rules in $EDITOR
redact check FILE...          # scan files against rules
```

Add `--global` for `~/.claude/` instead of project.

## Configuration

Create `.redaction_rules` (YAML, see `.redaction_rules.example` for more):

```yaml
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block              # or: redact
    description: AWS Access Key

  - id: email
    pattern: '[a-z]+@corp\.com'
    action: redact
    replacement: email         # or: ip, hostname, or literal string
    target: tool               # or: llm, both (default)
```

### Hashed secrets

To allow the filter list to be safely committed alongside the source code, the secrets within themselves can be hashed with `sha256`.

A regex can be configured via the `hash_extractor` setting. All possible matches in the input are then extracted, hashed, and compared against the filter list to be `block`ed or `redact`ed.

For hashed secrets (makes filter list safe to commit):
```bash
echo "SecretProjectName" | redact secret add --id project-name
```
