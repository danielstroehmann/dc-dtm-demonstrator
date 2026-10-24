# DTM Demonstrator

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
`--tls custom --tls-cert … --tls-key …`, `--port N`, `--yes` (no questions; a password is generated
and shown once), `--uninstall [--purge]`.

Settings live in `/opt/dtm-demonstrator/.env` (e.g. `SITE_HOSTS` for the certificate names). After editing it, reboot or run
`systemctl restart dtm-demonstrator` – the containers are recreated with the new values. Re-running
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
