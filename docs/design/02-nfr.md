# Non-functional requirements

> Status: draft for discussion, as of 2026-10-23. Project-specific NFRs; they take precedence
> over generic conventions where they conflict.

## NFR-1 Target platform and one-line setup (decided 2026-10-23)

- **Target:** a fresh **Ubuntu Server 26.04**, default *minimal* installation. Nothing else
  is assumed to be installed.
- **One command** takes such a server from zero to a running demonstrator:
  a) installs and configures all required tools, b) starts the demonstrator.
- The demonstrator is then **opened in a web browser**; the command prints the URL.
- The primary `README.md` shows this one-liner at the top.

### Proposal (to discuss)

```bash
# latest release
curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash

# specific release
curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash -s -- --version v1.2.0
```

| Topic | Proposal | Open question |
|---|---|---|
| Installed tools | **Only Docker Engine + Compose plugin** from Docker's apt repo (plus `ca-certificates`). No `git` – images come from GHCR. Everything else (openssl, jq, …) runs in containers | Verify: is `curl` part of 26.04 minimal? Otherwise the one-liner needs a `wget` variant |
| Idempotency | Re-running the one-liner is safe and acts as **update** (pull new images, keep `./data`, run migrations) | – |
| Versioning | **Explicit choice** (decided): the user picks what to install – a release tag (`--version vX.Y.Z`, default = latest release) or a branch (`--branch dev`). Never a silent install of `main`. Interactive run shows a selection (latest release preselected); flags skip it. `install.sh` is a release asset; images are published to GHCR per tag and per branch (e.g. `:v1.2.0`, `:branch-dev`). Enter on the preselected latest release counts as a choice (decided) | Branch images: `dev` only, see NFR-2 |
| Architecture | **amd64 only** (decided) | – |
| Install location | `/opt/dtm-demonstrator` with `./data` below | – |
| Web access & TLS | **Local network only** (decided). Reverse proxy container (e.g. Caddy) with a self-signed certificate | – |
| Authentication | **Built-in login** (decided): admin password generated at install and printed once – the UI controls a DTM API key and must never be open | – |
| DTM credentials | **Entered in the web UI on first start** (decided), stored under `./data` (never in the image) | – |

## NFR-2 Branch images (decided 2026-10-23: option A)

Wanted: branches are installable, images built on push **if it is fast** (decided 2026-10-23).
Conflicts with commons `git-workflow.md`: an ordinary push runs tests only, publishing happens
only on a `v*` tag.

Options:
- **A – preview images for `dev` only:** push to `dev` → tests → build + publish `:branch-dev`
  (no version, no release). With build cache and slim images expect ~2–4 min. Explicit,
  documented deviation from commons.
- **B – build on the target:** `--branch <name>` makes the installer build images locally from
  source. CI stays as in commons, but the install is slower and needs `git` on the server.
- **C – on demand:** a manual workflow (`workflow_dispatch`) publishes a branch image only when
  requested.

**Decided: A** – preview images for `dev` only; deviation from commons recorded in `CLAUDE.md`.
