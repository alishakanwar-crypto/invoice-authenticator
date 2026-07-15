# Invoice Integrity

Evidence-backed invoice authenticity, tampering and duplicate-detection dashboard.

The system does **not** claim that appearance alone proves an invoice is real. It combines:

- PDF/file integrity and metadata checks
- exact and near-duplicate matching
- invoice number, GSTIN and QR extraction
- visual compression signals
- sender traceability
- test-by-test human feedback
- manual ground-truth verdicts
- polished HTML email reports with feedback links

## Run locally

```bash
uv sync
uv run fastapi dev
```

Open `http://localhost:8000`.

## Configuration

Copy `.env.example` to `.env` and export its values before starting. SMTP is optional; without it,
the dashboard still provides an email preview.

Production deployments must set a strong `APP_SECRET`, use authenticated access, encrypted object
storage, malware scanning, PostgreSQL, regular backups and independently validated GST/IRP/vendor
integrations.

## Current evidence levels

The first release performs local, explainable tests. A result can be:

- `likely_genuine`
- `needs_review`
- `likely_tampered`

Authoritative `verified` status should only be introduced after cryptographic digital-signature,
IRP-signed QR, source-system or vendor-confirmation validation succeeds.

## Quality checks

```bash
uv run ruff check .
uv run mypy app
uv run pytest
```
