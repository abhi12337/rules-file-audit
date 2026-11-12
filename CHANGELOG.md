# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-12

### Changed

- RFA040 (VS Code): the message no longer claims that `"chat.tools.global.autoApprove": true`
  in a workspace's `.vscode/settings.json` turns approvals off for everyone who opens the
  workspace. VS Code honours that setting only in user settings and ignores it in workspace
  settings; it is still reported, because it shows approvals are meant to be off and is easily
  copied into user settings, where it applies to every workspace. `chat.tools.autoApprove` is
  now described as the old name of the setting, applied from workspace settings up to VS Code
  1.102 and no longer read by current versions. Both names are still detected.
- RFA041 (Claude Code): fixes and docs use the current permission rule syntax
  (`Bash(npm run test *)`, `Bash(curl *)`) instead of the older `:*` suffix. Both forms are
  still detected and classified the same way.

## [0.1.0] - 2026-11-11

First release.

### Added

- `rules-file-audit scan [PATH ...]`: static scan of folders or single files. Reads files
  only; no network access. The only program it runs is `git ls-files` (with
  `core.fsmonitor` disabled) for the tracking check.
- `rules-file-audit rules`: every rule with why it matters and how to fix it.
- Discovery of AI coding-assistant rules files (Cursor, Claude Code, Copilot, Codex /
  AGENTS.md, Gemini, Windsurf, Cline, Roo Code, Continue, Kiro, Junie, Amazon Q, Augment,
  Firebase Studio, OpenHands, Trae) and agent configs, in any folder of a repository.
- Invisible Unicode rules (run on every scanned file, never suppressible inline):
  - RFA001 Unicode tag characters and stacked variation selectors, with the hidden text decoded
  - RFA002 bidi overrides / embeddings / isolates (critical when they override or are unbalanced)
  - RFA003 zero-width and invisible formatting characters, with exemptions for emoji
    sequences, flags and scripts that need joiners or direction marks
- Hidden content rules: RFA010 HTML / markdown comments and CSS-hidden markup, RFA011 text
  pushed off-screen by whitespace, RFA012 base64 / hex blobs that decode to URLs or
  instructions.
- Instruction rules: RFA020 download-and-run, RFA021 exfiltration, RFA022 reading secrets,
  RFA023 concealment, RFA024 override phrases, RFA030 disabling tests / checks / TLS /
  approvals, RFA031 registry changes and URL installs, RFA032 install-time scripts, RFA051
  rules fetched from URLs. Clause-level negation handling and paragraph-level matching for
  hard-wrapped instructions.
- Agent permission rules: RFA040 approvals off (Claude Code `bypassPermissions`, VS Code
  `chat.tools.autoApprove`, Codex `approval_policy = "never"` / `danger-full-access`),
  RFA041 broad or dangerous auto-approved commands (Claude Code `permissions.allow`, VS Code
  `chat.tools.terminal.autoApprove`), RFA042 `enableAllProjectMcpServers`, RFA043
  `ANTHROPIC_BASE_URL` redirects, and RFA020-RFA022 on Claude Code hook / helper commands
  and MCP config command lines.
- RFA050 rules files not tracked by git.
- Text and JSON reports in which every invisible character is written as `<U+XXXX>`, an exact
  fix per finding (including a one-liner that removes exactly the characters found),
  `--fail-on`, `--min-severity`, `--disable`, `--exclude`, `--brief`, `--no-color`,
  `rules-file-audit: ignore` comments (counted in the report), exit codes `0` / `1` / `2`.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
