# Demonstrator · Device Trust Manager

A demonstrator for **DigiCert® Device Trust Manager (DTM)**: it runs typical DTM use cases
end to end – configuration in DTM, simulated devices (one container each) that obtain and
use certificates, live observation – and rolls everything back afterwards with one click.

> **Status: v0.1 in development** – UC-1 and UC-2 work end to end; no release published yet.

## Install

On a fresh Ubuntu Server 26.04 (minimal installation), one command prepares the machine (Docker),
asks for the initial login password and the host names for the HTTPS certificate, and starts the
demonstrator:

```bash
curl -fsSL https://raw.githubusercontent.com/danielstroehmann/dc-dtm-demonstrator/dev/install.sh | sudo bash -s -- --branch dev
```

This installs the current development preview (`dev`). Once the first release is published, the
latest release installs with:

```bash
curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash
```

Then open one of the printed URLs. Options: `--version vX.Y.Z`, `--host NAME` (repeatable),
`--tls-cert … --tls-key …` (own PEM pair), `--port N`, `--http-port N` (plain HTTP, redirects to HTTPS; default 80), `--yes` (no questions; a password is generated
and shown once), `--uninstall [--purge]`.

Settings live in `/opt/dtm-demonstrator/.env` (e.g. `SITE_HOSTS` for the certificate names). After editing it, reboot or run
`systemctl restart dtm-demonstrator` – the containers are recreated with the new values.

**TLS** is set in the same `.env`: `TLS_CERT_FILE` and `TLS_KEY_FILE` point to a PEM certificate (with chain) and
key – by default a self-signed pair the installer created in `./tls`; point them to your own files, e.g. from
Let's Encrypt. Alternatively clear both and set `TLS_PKCS12_FILE` and `TLS_PKCS12_PASSWORD` (PEM wins when both are
set). The files are checked and loaded at every `systemctl restart dtm-demonstrator`; if something is wrong,
`docker compose -p dtm-demonstrator logs tls` says what. Re-running
the one-liner updates the installation and keeps data, password and settings.

## Documentation

- [Vision](docs/design/01-vision.md) – goals, use-case catalog, high-level architecture, decisions, open questions
- [Non-functional requirements](docs/design/02-nfr.md) – target platform, one-line setup
- [UC-1 Evergreen Device IDs for Factory Provisioning](docs/design/uc-01-evergreen.md) – requirements and open questions
- [UC-2 Evergreen Device IDs with Factory-Generated Keys](docs/design/uc-02-factory-keys.md) – client-side keys (CSRs)
- [Risks and test cases](docs/design/03-risks-and-tests.md) – known risks, required live tests
- [DTM API overview](docs/research/dtm-api-overview.md) – research notes on the DTM APIs
- [DTM API endpoint index](docs/research/dtm-api-endpoints.md) – generated from the public OpenAPI spec

## License

[MIT](LICENSE)
