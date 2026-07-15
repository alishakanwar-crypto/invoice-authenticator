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
cp .env.example .env
# Replace APP_SECRET and ADMIN_PASSWORD, then:
set -a && source .env && set +a
uv run fastapi dev
```

Open `http://localhost:8000`.

## Configuration

Copy `.env.example` to `.env`, replace the required secrets and export its values before starting.
The application refuses to start without an admin password or with the development-only signing
secret. SMTP is optional; without it, the dashboard still provides an email preview.

Dashboard routes require a signed admin session, state-changing forms require CSRF tokens, feedback
links expire and are single-use, and CPU-heavy analysis/email routes have baseline rate limits.
Production deployments should additionally use encrypted object storage, malware scanning,
PostgreSQL, shared Redis rate limiting, regular backups and independently validated GST/IRP/vendor
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
