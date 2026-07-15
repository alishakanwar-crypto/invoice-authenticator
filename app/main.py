import asyncio
import hmac
import re
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from functools import partial
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import IST, ROOT_DIR, settings
from app.database import (
    add_feedback,
    consume_feedback_token,
    create_invoice,
    get_invoice,
    get_test_results,
    initialize_database,
    list_invoices,
    mark_report_sent,
    save_test_results,
    update_invoice_analysis,
    update_manual_review,
)
from app.email_service import render_report_email, send_report, verify_feedback_token
from app.forensics import analyze_invoice

ALLOWED_MIME_TYPES = {"application/pdf", "image/jpeg", "image/png"}
ALLOWED_SUFFIXES = {".pdf", ".jpg", ".jpeg", ".png"}
FEEDBACK_RESPONSES = {"correct", "should_pass", "should_fail", "not_enough_evidence"}
MANUAL_VERDICTS = {"", "real", "tampered", "duplicate", "inconclusive"}
SESSION_COOKIE = "invoice_integrity_session"
PUBLIC_PATHS = {"/health", "/login", "/feedback/email"}
ANALYSIS_SLOTS = asyncio.Semaphore(2)
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def _content_matches_type(content: bytes, mime_type: str) -> bool:
    signatures = {
        "application/pdf": (b"%PDF-",),
        "image/jpeg": (b"\xff\xd8\xff",),
        "image/png": (b"\x89PNG\r\n\x1a\n",),
    }
    return content.startswith(signatures[mime_type])


def _signature(payload: str) -> str:
    return hmac.new(
        settings.app_secret.encode(),
        payload.encode(),
        sha256,
    ).hexdigest()


def _session_token(expires_at: int) -> str:
    payload = f"{settings.admin_username}:{expires_at}"
    return f"{expires_at}.{_signature(payload)}"


def _valid_session(token: str) -> bool:
    try:
        expires_text, signature = token.split(".", 1)
        expires_at = int(expires_text)
    except (TypeError, ValueError):
        return False
    if expires_at < int(datetime.now(IST).timestamp()):
        return False
    expected = _signature(f"{settings.admin_username}:{expires_at}")
    return hmac.compare_digest(expected, signature)


def _csrf_token(session_token: str) -> str:
    return _signature(f"csrf:{session_token}")


def _verify_csrf(request: Request, token: str) -> None:
    session_token = request.cookies.get(SESSION_COOKIE, "")
    if not session_token or not hmac.compare_digest(_csrf_token(session_token), token):
        raise HTTPException(403, "Invalid or missing CSRF token.")


def _login_csrf_token() -> str:
    return _signature(f"login:{datetime.now(IST).date().isoformat()}")


def _verify_login_csrf(token: str) -> None:
    today = datetime.now(IST).date()
    valid_tokens = {
        _signature(f"login:{day.isoformat()}")
        for day in (today, today - timedelta(days=1))
    }
    if not any(hmac.compare_digest(token, valid) for valid in valid_tokens):
        raise HTTPException(403, "Invalid login request.")


def _enforce_rate_limit(request: Request, action: str, limit: int, window: int) -> None:
    client = request.client.host if request.client else "unknown"
    key = f"{action}:{client}"
    now = monotonic()
    bucket = RATE_BUCKETS[key]
    while bucket and bucket[0] <= now - window:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(429, "Too many requests. Please try again later.")
    bucket.append(now)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if not settings.admin_password:
        raise RuntimeError("ADMIN_PASSWORD must be configured before the app can start.")
    if settings.app_secret == "local-development-only-change-me":
        raise RuntimeError("APP_SECRET must be replaced before the app can start.")
    initialize_database()
    yield


app = FastAPI(title="Invoice Integrity", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=ROOT_DIR / "app" / "templates")


def _format_ist(value: str | None) -> str:
    if not value:
        return ""
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=IST)
    return timestamp.astimezone(IST).strftime("%d-%m-%Y %H:%M IST")


templates.env.filters["format_ist"] = _format_ist


@app.middleware("http")
async def require_dashboard_auth(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    path = request.url.path
    is_public = path in PUBLIC_PATHS or path.startswith("/static/")
    session_token = request.cookies.get(SESSION_COOKIE, "")
    if not is_public and not _valid_session(session_token):
        if request.method == "GET":
            return RedirectResponse("/login", status_code=303)
        return Response("Authentication required.", status_code=401)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'"
    )
    return response


def _safe_filename(filename: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)
    return stem[:180] or "invoice"


def _template_context(request: Request, values: dict[str, object]) -> dict[str, object]:
    session_token = request.cookies.get(SESSION_COOKIE, "")
    return {**values, "csrf_token": _csrf_token(session_token) if session_token else ""}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {"login_csrf_token": _login_csrf_token()},
    )


@app.post("/login")
async def login(
    request: Request,
    username: Annotated[str, Form(max_length=120)],
    password: Annotated[str, Form(max_length=300)],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _enforce_rate_limit(request, "login", 10, 600)
    _verify_login_csrf(csrf_token)
    if not (
        hmac.compare_digest(username, settings.admin_username)
        and hmac.compare_digest(password, settings.admin_password)
    ):
        raise HTTPException(401, "Invalid username or password.")
    expires_at = int(
        (datetime.now(IST) + timedelta(hours=settings.session_hours)).timestamp()
    )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        _session_token(expires_at),
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.public_base_url.startswith("https://"),
        samesite="strict",
    )
    return response


@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _verify_csrf(request, csrf_token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    search: Annotated[str, Query(max_length=120)] = "",
    verdict: Annotated[str, Query(max_length=30)] = "",
) -> HTMLResponse:
    invoices = list_invoices(search=search.strip(), verdict=verdict.strip())
    counts = {
        "total": len(invoices),
        "likely_genuine": sum(row["verdict"] == "likely_genuine" for row in invoices),
        "needs_review": sum(row["verdict"] == "needs_review" for row in invoices),
        "likely_tampered": sum(row["verdict"] == "likely_tampered" for row in invoices),
    }
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _template_context(
            request,
            {"invoices": invoices, "counts": counts, "search": search, "verdict": verdict},
        ),
    )


@app.post("/invoices")
async def upload_invoice(
    request: Request,
    file: Annotated[UploadFile, File()],
    csrf_token: Annotated[str, Form()],
    sender_name: Annotated[str, Form(max_length=120)] = "",
    sender_email: Annotated[str, Form(max_length=254)] = "",
    report_email: Annotated[str, Form(max_length=254)] = "",
    vendor_name: Annotated[str, Form(max_length=160)] = "",
    notes: Annotated[str, Form(max_length=1500)] = "",
) -> RedirectResponse:
    _verify_csrf(request, csrf_token)
    _enforce_rate_limit(request, "upload", 8, 600)
    original_filename = _safe_filename(file.filename or "invoice")
    suffix = Path(original_filename).suffix.lower()
    mime_type = file.content_type or "application/octet-stream"
    if suffix not in ALLOWED_SUFFIXES or mime_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(415, "Upload a PDF, JPG or PNG invoice.")

    maximum_size = settings.max_upload_mb * 1024 * 1024
    content = await file.read(maximum_size + 1)
    await file.close()
    if not content:
        raise HTTPException(400, "The uploaded file is empty.")
    if len(content) > maximum_size:
        raise HTTPException(413, f"Files are limited to {settings.max_upload_mb} MB.")
    if not _content_matches_type(content, mime_type):
        raise HTTPException(
            415,
            "The file contents do not match the declared PDF or image type.",
        )

    file_hash = sha256(content).hexdigest()
    stored_name = f"{file_hash[:16]}-{original_filename}"
    stored_path = settings.upload_dir / stored_name
    if not stored_path.exists():
        stored_path.write_bytes(content)

    invoice_id = create_invoice(
        original_filename=original_filename,
        stored_path=stored_path,
        mime_type=mime_type,
        file_size=len(content),
        sha256=file_hash,
        sender_name=sender_name.strip(),
        sender_email=sender_email.strip(),
        report_email=report_email.strip(),
        vendor_name=vendor_name.strip(),
        notes=notes.strip(),
    )
    async with ANALYSIS_SLOTS:
        analysis = await asyncio.to_thread(
            partial(
                analyze_invoice,
                stored_path,
                mime_type=mime_type,
                invoice_id=invoice_id,
                sender_name=sender_name.strip(),
                sender_email=sender_email.strip(),
            )
        )
    save_test_results(invoice_id, analysis.tests)
    update_invoice_analysis(
        invoice_id,
        perceptual_hash=analysis.perceptual_hash,
        invoice_number=analysis.fields.invoice_number,
        invoice_date=analysis.fields.invoice_date,
        amount=analysis.fields.amount,
        gstin=analysis.fields.gstin,
        verdict=analysis.verdict,
        risk_score=analysis.risk_score,
        summary=analysis.summary,
    )

    invoice = get_invoice(invoice_id)
    tests = get_test_results(invoice_id)
    if (
        invoice is not None
        and report_email.strip()
        and await send_report(invoice, tests, report_email.strip())
    ):
        mark_report_sent(invoice_id)
    return RedirectResponse(f"/invoices/{invoice_id}", status_code=303)


@app.get("/invoices/{invoice_id}", response_class=HTMLResponse)
async def invoice_detail(request: Request, invoice_id: int) -> HTMLResponse:
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice not found.")
    tests = get_test_results(invoice_id)
    return templates.TemplateResponse(
        request,
        "invoice_detail.html",
        _template_context(request, {"invoice": invoice, "tests": tests}),
    )


@app.get("/invoices/{invoice_id}/email-preview", response_class=HTMLResponse)
async def email_preview(invoice_id: int) -> HTMLResponse:
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice not found.")
    return HTMLResponse(render_report_email(invoice, get_test_results(invoice_id)))


@app.post("/invoices/{invoice_id}/send-report")
async def send_invoice_report(
    request: Request,
    invoice_id: int,
    recipient: Annotated[str, Form(max_length=254)],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _verify_csrf(request, csrf_token)
    _enforce_rate_limit(request, "email", 5, 3600)
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice not found.")
    if not await send_report(invoice, get_test_results(invoice_id), recipient.strip()):
        raise HTTPException(503, "SMTP is not configured. Use the email preview for now.")
    mark_report_sent(invoice_id)
    return RedirectResponse(f"/invoices/{invoice_id}?sent=1", status_code=303)


@app.post("/invoices/{invoice_id}/feedback")
async def submit_feedback(
    request: Request,
    invoice_id: int,
    response: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    test_result_id: Annotated[int, Form()] = 0,
    explanation: Annotated[str, Form(max_length=1500)] = "",
    reviewer_name: Annotated[str, Form(max_length=120)] = "",
) -> RedirectResponse:
    _verify_csrf(request, csrf_token)
    if response not in FEEDBACK_RESPONSES:
        raise HTTPException(400, "Invalid feedback response.")
    if get_invoice(invoice_id) is None:
        raise HTTPException(404, "Invoice not found.")
    add_feedback(
        invoice_id=invoice_id,
        test_result_id=test_result_id or None,
        response=response,
        explanation=explanation.strip(),
        reviewer_name=reviewer_name.strip(),
        source="dashboard",
    )
    return RedirectResponse(f"/invoices/{invoice_id}#test-{test_result_id}", status_code=303)


@app.post("/invoices/{invoice_id}/manual-review")
async def manual_review(
    request: Request,
    invoice_id: int,
    verdict: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    notes: Annotated[str, Form(max_length=2000)] = "",
) -> RedirectResponse:
    _verify_csrf(request, csrf_token)
    if verdict not in MANUAL_VERDICTS:
        raise HTTPException(400, "Invalid manual verdict.")
    if get_invoice(invoice_id) is None:
        raise HTTPException(404, "Invoice not found.")
    update_manual_review(invoice_id, verdict, notes.strip())
    return RedirectResponse(f"/invoices/{invoice_id}#manual-review", status_code=303)


@app.get("/feedback/email", response_class=HTMLResponse)
async def email_feedback(
    request: Request,
    invoice_id: int,
    test_result_id: int,
    response: str,
    expires_at: int,
    token: str,
) -> HTMLResponse:
    if response not in FEEDBACK_RESPONSES or not verify_feedback_token(
        invoice_id,
        test_result_id or None,
        response,
        expires_at,
        token,
    ):
        raise HTTPException(403, "This feedback link is invalid or expired.")
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice not found.")
    return templates.TemplateResponse(
        request,
        "feedback_confirm.html",
        {
            "invoice": invoice,
            "test_result_id": test_result_id,
            "response": response,
            "expires_at": expires_at,
            "token": token,
        },
    )


@app.post("/feedback/email", response_class=HTMLResponse)
async def confirm_email_feedback(
    request: Request,
    invoice_id: Annotated[int, Form()],
    test_result_id: Annotated[int, Form()],
    response: Annotated[str, Form()],
    expires_at: Annotated[int, Form()],
    token: Annotated[str, Form()],
) -> HTMLResponse:
    if response not in FEEDBACK_RESPONSES or not verify_feedback_token(
        invoice_id,
        test_result_id or None,
        response,
        expires_at,
        token,
    ):
        raise HTTPException(403, "This feedback link is invalid or expired.")
    if not consume_feedback_token(sha256(token.encode()).hexdigest()):
        raise HTTPException(409, "This feedback link has already been used.")
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice not found.")
    add_feedback(
        invoice_id=invoice_id,
        test_result_id=test_result_id or None,
        response=response,
        explanation="",
        reviewer_name="",
        source="email",
    )
    return templates.TemplateResponse(
        request,
        "feedback_thanks.html",
        {"invoice": invoice, "response": response.replace("_", " ")},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
