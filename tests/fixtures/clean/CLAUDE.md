# CLAUDE.md

<!-- markdownlint-disable MD013 -->

This file gives Claude Code guidance for working in this repository.

## Commands

- `npm run dev` starts the app on http://localhost:3000
- `npm test` runs the unit tests; `npm run test:e2e` runs Playwright
- `npm run lint` and `npm run typecheck` must pass before you commit
- Health check: `curl http://localhost:3000/api/health` should return `{"ok":true}`

## Rules

- Never commit `.env`. Copy `.env.example` to `.env` and fill in the values locally.
- Do not skip tests, and never use `git commit --no-verify`.
- Don't disable lint rules to make an error go away; fix the code instead.
- Never print or log tokens, API keys or passwords.
- Never read `~/.ssh` or any file outside this repository.
- Do not change files outside `src/` without asking the user first.
- Never delete files without telling the user.
- Skip tests for docs-only changes (README, comments).
- The retry helper silently ignores network errors; do not silently swallow exceptions in new code.
- Read the OpenAI key from the `OPENAI_API_KEY` environment variable on the server only.
- The frontend sends the session token in the `Authorization` header; never put tokens in URLs.
- Include `.env` in `.gitignore` (it already is).
- Follow the Conventional Commits spec (https://www.conventionalcommits.org/en/v1.0.0/).

## Calling the GitHub API in scripts

```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/acme/web/pulls
gh api repos/acme/web/issues --jq '.[].title'
```

<!-- TODO: document the deploy pipeline -->

<details>
<summary>Architecture notes</summary>

The API lives in `packages/api`, the web app in `apps/web`. Shared types are in
`packages/types`. We use React hooks for state; remove unused hooks when you touch a file.

</details>

Example HTML template (shown literally, the comment is part of the example):

```html
<!-- page header -->
<div style="display:none" id="tooltip-template">Tooltip</div>
```

Release checksum format (sha256): 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
