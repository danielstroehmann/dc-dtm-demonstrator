# dc-dtm-demonstrator

<!-- BEGIN commons (managed by commons-init) -->
## Shared conventions (imported from stroehmi-claude-commons)
Managed block — do NOT edit the imported rules here. Edit the source repo
and run 'commons-sync'. Project-specific rules go BELOW the END marker.

@.claude/commons/agent-efficiency.md
@.claude/commons/code-style.md
@.claude/commons/deployment.md
@.claude/commons/git-workflow.md
@.claude/commons/security.md
@.claude/commons/testing.md
@.claude/commons/ui-ux.md
<!-- END commons -->

## Project-specific conventions

<!--
  Add rules that apply ONLY to this project below (stack, domain quirks, local
  commands, deployment specifics). The commons block ABOVE is managed: to change
  an imported rule, edit the source in stroehmi-claude-commons and run
  'commons-sync' here — do not edit the copies in .claude/commons/ directly.
-->

### Language (overrides commons ui-ux / code-style)

- Repo, docs and solution are **fully English**: UI texts, code, logs, documentation,
  commit messages. This deliberately overrides
  the commons rule "all UI texts German" — the demonstrator is shown to international
  customers.
- Chat with the author is German.

### Deployment (overrides commons deployment / security)

- Target is a fresh **Ubuntu Server 26.04 minimal**, amd64, local network only – not the
  home-lab. No Authentik, no `shared-net`, no external reverse proxy: the demonstrator
  brings its own reverse proxy (self-signed TLS) and built-in login.
- Setup and update via one-line installer – see `docs/design/02-nfr.md` (NFR-1).
- CI deviation from commons git-workflow: a push to `dev` runs tests **and** publishes a
  preview image `:branch-dev` (no version, no release). Releases still only via `v*` tag (NFR-2).

### DTM account scoping (global, all use cases)

- The API key has access to **several DTM accounts**. Every DTM call must be explicitly
  scoped to the configured account (`account_id`) – never rely on a default account.
  Cleanup must never touch objects outside that account.
- **DTM blueprints are forbidden.** Never call, execute or build on the blueprint service –
  ignore it entirely. Create DTM objects with the regular management APIs only.
- **Existing CAs are read-only.** The account's root/issuing CAs (ECDSA and RSA) are used
  for issuance but never created, modified, disabled or deleted by this project.
- Keep the test account clean: remove everything a test creates.
- Test credentials live only in the local, gitignored `.env` – never in chat logs, docs or commits.

### Public repository

- The repo is **public on GitHub, also during development**. Never commit secrets, tenant
  or account IDs, hostnames of private infrastructure, or customer names.
- `.claude/commons/` is **local only** (gitignored) – the imports above resolve on the
  author's machine only.
- Commits use the GitHub noreply address; a gitleaks pre-commit hook (`.githooks/`,
  enable with `git config core.hooksPath .githooks`) blocks secrets.

### Phase

- Architecture and design phase (since 2026-10-23): document and discuss only, no
  implementation until the author says so.
