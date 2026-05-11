# Changelog

All notable changes to `claude-code-redaction-hooks` are listed here.

## 0.4.0 — 2026-05-11

- **New hook events**: `UserPromptExpansion` and `PostToolBatch` are
  scanned. Without these, two leak paths bypassed all earlier coverage:
  - `UserPromptExpansion` fires on `/skillname args` slash-command
    expansions and bypasses both `UserPromptSubmit` and `PreToolUse`.
    No `updatedInput` per CC docs, so `redact`-action matches surface as
    `redact-skipped` audits + `additionalContext` warning.
  - `PostToolBatch` fires after a parallel tool batch resolves. Per-entry
    `tool_response` is a serialized string or content-block array (not
    the structured Output shape `PostToolUse` uses), so every string leaf
    is walked. Outputs are already shipped to context, so `redact`-action
    matches surface as `redact-skipped`.
- **Behaviour fix — session halt on block match**: `PreToolUse`,
  `UserPromptSubmit`, `PreCompact`, and the new `PostToolBatch` /
  `UserPromptExpansion` handlers now exit 0 with
  `continue: false` + `stopReason` instead of exit 2. Per CC docs, exit 2
  silently drops the JSON body and only feeds stderr to Claude — the
  intended halt-the-session behaviour never fired and the model could
  retry. Empirically verified on CC 2.1.138: exit 0 + `continue: false`
  halts subsequent turns. `PostToolUse` intentionally stays on exit 2:
  the tool has already executed, so halting only delays the next turn
  rather than un-shipping the leak.
  - **Caveat**: within a parallel tool batch, every call's `PreToolUse`
    still fires (and is individually denied via `permissionDecision: deny`)
    before the halt takes effect on the *next* batch. Acceptable for
    redaction — no leak fires — but operators should know the halt is
    not instantaneous within a batch.
- **Internal**: new `build_decision_block_response` helper in
  `handlers/_common.py` centralises the top-level `decision: "block"`
  response shape used by `UserPromptSubmit`, `UserPromptExpansion`,
  `PostToolBatch`, and `PreCompact`.
- **Verify harness**: `redact verify-cc-schema` gains a
  `block-pre-tool-use` scenario (drives the halt path live so the
  captured fixture covers the deny + `continue: false` JSON shape) and a
  `post-tool-batch-parallel` scenario. The `PostToolBatch` fixture lands
  in `tests/fixtures/cc-payloads/`. The `UserPromptExpansion` fixture is
  deferred — CC headless `-p` mode does not expand custom slash commands
  the same way as the interactive REPL.

## 0.3.0 — 2026-05-10

- **Behaviour fix**: every handler that detects a `redact`-action match
  but cannot rewrite the payload now audits as `redact-skipped` (matching
  the README contract). Affects `UserPromptSubmit`, `PostToolUse`
  (non-dict / no-change branches), `PostToolUseFailure`, `PreCompact`,
  `PostCompact`, `InstructionsLoaded`, `Stop`, `SubagentStop`. The
  `PostToolUse` success path that produces a real `updatedToolOutput`
  still audits as `redact`. Operator queries against
  `redact audit since 7d | jq 'select(.action=="redact")'` now reliably
  reflect "rewrite happened" rather than "rule matched somewhere".
- **Security fix**: `path_pattern` rules for `Bash` now see paths inside
  `bash -c "<inner>"` / `sh -c '<inner>'` / `dash`/`zsh`/`ksh` wrappers
  (incl. `env VAR=x bash -c …` and `-c=<inner>` forms). Previously the
  inner command landed as a single shlex token and silently bypassed the
  matcher.
- **CLI**: `redact secret add` now exposes `--action {block,redact,warn}`,
  `--target {llm,tool,both}`, `--hash-extractor REGEX`, and
  `--replacement STR`. Hashed redact-style rules no longer require
  hand-editing.
- **CLI**: `redact hook` defaults to `Path.cwd()` when
  `$CLAUDE_PROJECT_DIR` is unset (previously fell back to the user-global
  audit log, which `redact audit tail` doesn't read by default). Manual
  hook invocations from a project shell now show up in
  `redact audit tail` as expected.
- **Docs**: README documents the threat model for hashed rules
  (brute-forceable for low-entropy inputs) and warns that
  `redact secret add` re-serialises the rules file via `yaml.dump`
  (drops comments).
- **Internal**: `hooks.py` (1530 lines) split into a `handlers/` package
  plus `extractors.py` and `drift.py`. `handle_pre_tool_use` (was CCN 59)
  and `iter_output_fields` (was CCN 42) are decomposed; no behaviour
  change. Test imports updated; the public API reachable via
  `redaction_hooks.run_hook` is unchanged.
- `__version__` is now sourced from `importlib.metadata` so
  `pyproject.toml` is the single source of truth.

## 0.2.0 — 2026-05-10

- **Behaviour fix**: `PreToolUse` and `PostToolUse` hooks no longer ship
  with a hard-coded tool matcher. Earlier versions installed
  `matcher: "Write|Edit|Bash"` (PreToolUse) and
  `matcher: "Read|Bash|Grep|Glob|WebFetch"` (PostToolUse), which silently
  bypassed `Read`, `MultiEdit`, `WebSearch`, `Task`/Agent, and MCP
  `mcp__*__*` tools. Rules with `tool: Read` or `file_tools: read` now
  fire as the README has always documented. Re-run `redact claude-setup`
  (or `--uninstall && claude-setup`) to refresh existing installs.
- **New hook events**: `PostToolUseFailure`, `PostCompact`, `Stop`,
  `SubagentStop`, and `InstructionsLoaded` are scanned (warn-only — see
  README "Limitations"). They detect leaks in failed-tool errors,
  post-compaction summaries, the last assistant message, and loaded
  `CLAUDE.md` / `.claude/rules/*.md` files.
- **Spilled tool output**: when Claude Code persists a tool result
  >50K chars to disk, the redaction hook now reads the spill file and
  applies block rules; redact rules surface a `redact-skipped` audit
  entry rather than silently passing.
- **`additionalContext`** is now sent on `PreToolUse` redacts and
  `UserPromptSubmit` redacts so the model knows a rule fired (rule IDs
  only, never matched text).
- **`tool_use_id`** is recorded in audit entries for pre/post correlation.
- **`$CLAUDE_PROJECT_DIR`** is honoured by `redact hook` when set,
  anchoring rules and audit log to the project root regardless of the
  hook process's cwd.
