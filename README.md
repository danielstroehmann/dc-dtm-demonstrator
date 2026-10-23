# DTM Demonstrator

A demonstrator for **DigiCert® Device Trust Manager (DTM)**: it runs typical DTM use cases
end to end – configuration in DTM, simulated devices (one container each) that obtain and
use certificates, live observation – and rolls everything back afterwards with one click.

> **Status: architecture & design phase.** There is no code yet – only design documents.

## Quick start (planned)

On a fresh Ubuntu Server 26.04 (minimal installation), one command prepares the machine and
starts the demonstrator:

```bash
curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash
```

A specific version: append `-s -- --version vX.Y.Z` to `sudo bash`.

Then open the URL printed at the end in your browser. *(Not available yet – see
[NFRs](docs/design/02-nfr.md).)*

## Documentation

- [Vision](docs/design/01-vision.md) – goals, use-case catalog, high-level architecture, decisions, open questions
- [Non-functional requirements](docs/design/02-nfr.md) – target platform, one-line setup
- [DTM API overview](docs/research/dtm-api-overview.md) – research notes on the DTM APIs
- [DTM API endpoint index](docs/research/dtm-api-endpoints.md) – generated from the public OpenAPI spec

## License

[MIT](LICENSE)
