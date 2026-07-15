---
name: testing-invoice-dashboard
description: Test the Invoice Integrity dashboard end-to-end, including PDF/image OCR, evidence feedback, email reports, duplicate calibration, audit history, and logout protection.
---

# Testing the Invoice Integrity dashboard

## Devin Secrets Needed

- `APP_SECRET`: strong test-only signing secret required at startup.
- `ADMIN_PASSWORD`: local authorized-reviewer password.
- `INVOICE_DASHBOARD_ADMIN_PASSWORD`: repository-scoped password for the permanent dashboard.
- `FLY_API_TOKEN`: only needed to deploy or inspect the Fly.io production runtime.
- `SMTP_USERNAME` and `SMTP_PASSWORD`: only needed when testing a real SMTP provider. Omit them when using the local SMTP sink.

Never print or commit secret values. Use isolated test data and upload directories rather than the repository defaults.

## Environment

1. Install project dependencies with `uv sync`.
2. Confirm Tesseract is available with `tesseract --version`.
3. Start a local SMTP sink with system Python when production SMTP receipt is outside scope:

   ```bash
   /usr/bin/python3 -m smtpd -n -c DebuggingServer 127.0.0.1:1025
   ```

   Pyenv Python versions may not include the deprecated `smtpd` module, while `/usr/bin/python3` may still provide it.

4. Start the app with explicit isolated paths and SMTP settings:

   ```bash
   APP_SECRET="$APP_SECRET" \
   ADMIN_USERNAME=admin \
   ADMIN_PASSWORD="$ADMIN_PASSWORD" \
   DATA_DIR=/home/ubuntu/invoice-e2e-data \
   UPLOAD_DIR=/home/ubuntu/invoice-e2e-uploads \
   PUBLIC_BASE_URL=http://127.0.0.1:8000 \
   SMTP_HOST=127.0.0.1 \
   SMTP_PORT=1025 \
   SMTP_USE_TLS=false \
   uv run fastapi dev --host 127.0.0.1 --port 8000
   ```

5. Use `http://127.0.0.1:8000/health` to verify readiness.

## Fixture preparation

- Keep one received PDF with known invoice number, date, total, and GSTIN values.
- Derive one grayscale, JPEG-compressed image from that PDF to exercise the printer-scan/OCR path.
- Validate the image fixture with the same OCR/extraction code before recording; fixture-generation mistakes should not be confused with product failures.
- Re-upload the exact PDF bytes to exercise SHA-256 duplicate detection.

## Browser test

1. Authenticate before recording and confirm the isolated dashboard is empty.
2. Maximize Chrome and start one continuous annotated recording.
3. Upload the PDF with a known sender and the single user-approved email address.
4. Verify the generated test number, conservative verdict, risk, extracted values, evidence ledger, and `Asia/Kolkata` timestamp.
5. Save one per-test response and one human-ground-truth verdict; confirm both persist after reload.
6. Send the report through the configured SMTP path and open the HTML preview. Verify the recipient handoff separately from external mailbox receipt.
7. Re-upload the exact PDF. It should be `needs review`, not `likely tampered`, and should reference the earlier test number.
8. Upload the scan-like JPEG. Verify OCR values and expect a conservative duplicate-related `needs review` result when its invoice number already exists.
9. Verify final counters and all history rows, then sign out and confirm the protected login page replaces the workspace.
10. Stop the recording and preserve full-screen screenshots of the baseline result, email preview, duplicate result, JPEG result, audit history, and logout page.

## Production deployment smoke test

1. Confirm the public `/health` endpoint, Fly machine region, and encrypted persistent volume
   before browser testing.
2. Test the public root while signed out. It should redirect to the styled HTTPS login page and
   must not reveal dashboard data.
3. Inspect generated asset URLs when a deployment is behind an HTTPS proxy. If FastAPI generates
   `http://` static links, the stylesheet may be blocked as mixed content; configure Uvicorn proxy
   headers and retest from a fresh page load.
4. Authenticate with the repository-scoped administrator password and verify exact clean-state
   counters and upload history before adding any fixtures.
5. Preserve production data by avoiding uploads during a deployment-only smoke test when the full
   upload workflow has already passed against the same image and application code.
6. Verify sign-out returns to the protected login page.

## Reporting

- State SMTP handoff separately from external inbox delivery.
- Report authoritative GST/IRP lookup and certificate validation as untested unless they were actually exercised.
- Post one PR comment with embedded visual evidence and the Devin session link.
- Produce `test-report.md` with inline screenshots and attach it with the annotated recording.
