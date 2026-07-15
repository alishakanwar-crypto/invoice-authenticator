import hmac
import sqlite3
from datetime import datetime, timedelta
from email.message import EmailMessage
from hashlib import sha256
from html import escape

import aiosmtplib

from app.config import IST, settings


def feedback_expiry() -> int:
    expiry = datetime.now(IST) + timedelta(days=settings.feedback_link_days)
    return int(expiry.timestamp())


def feedback_token(
    invoice_id: int,
    test_result_id: int | None,
    response: str,
    expires_at: int,
) -> str:
    payload = f"{invoice_id}:{test_result_id or 0}:{response}:{expires_at}"
    return hmac.new(
        settings.app_secret.encode(),
        payload.encode(),
        sha256,
    ).hexdigest()


def verify_feedback_token(
    invoice_id: int,
    test_result_id: int | None,
    response: str,
    expires_at: int,
    token: str,
) -> bool:
    if expires_at < int(datetime.now(IST).timestamp()):
        return False
    return hmac.compare_digest(
        feedback_token(invoice_id, test_result_id, response, expires_at),
        token,
    )


def _feedback_url(
    invoice_id: int,
    test_result_id: int | None,
    response: str,
    expires_at: int,
) -> str:
    token = feedback_token(invoice_id, test_result_id, response, expires_at)
    return (
        f"{settings.public_base_url}/feedback/email?"
        f"invoice_id={invoice_id}&test_result_id={test_result_id or 0}"
        f"&response={response}&expires_at={expires_at}&token={token}"
    )


def _report_row(invoice_id: int, test: sqlite3.Row, expires_at: int) -> str:
    correct_url = _feedback_url(invoice_id, int(test["id"]), "correct", expires_at)
    pass_url = _feedback_url(invoice_id, int(test["id"]), "should_pass", expires_at)
    fail_url = _feedback_url(invoice_id, int(test["id"]), "should_fail", expires_at)
    return f"""
        <tr>
          <td style="padding:12px;border-bottom:1px solid #e8efe9">
            <strong>{escape(str(test["test_name"]))}</strong><br>
            <span style="color:#68756b;font-size:12px">{escape(str(test["evidence"]))}</span>
          </td>
          <td style="padding:12px;border-bottom:1px solid #e8efe9;text-transform:capitalize">
            {escape(str(test["status"]).replace("_", " "))}
          </td>
          <td style="padding:12px;border-bottom:1px solid #e8efe9;white-space:nowrap">
            <a href="{correct_url}" style="color:#087f5b">Correct</a> ·
            <a href="{pass_url}" style="color:#087f5b">Should pass</a> ·
            <a href="{fail_url}" style="color:#087f5b">Should fail</a>
          </td>
        </tr>
    """


def render_report_email(invoice: sqlite3.Row, tests: list[sqlite3.Row]) -> str:
    expires_at = feedback_expiry()
    verdict_labels = {
        "likely_genuine": "Likely genuine",
        "needs_review": "Needs review",
        "likely_tampered": "Likely tampered",
        "verified": "Verified",
    }
    colors = {
        "likely_genuine": "#18864b",
        "needs_review": "#b7791f",
        "likely_tampered": "#c53030",
        "verified": "#087f5b",
    }
    verdict = str(invoice["verdict"])
    rows = "".join(_report_row(int(invoice["id"]), test, expires_at) for test in tests)
    return f"""
    <!doctype html>
    <html>
      <body style="margin:0;background:#f3f7f4;font-family:Arial,sans-serif;color:#193126">
        <div style="max-width:760px;margin:0 auto;padding:28px 14px">
          <div style="background:#0b5f3c;color:white;padding:24px 28px;border-radius:16px 16px 0 0">
            <div style="font-size:13px;letter-spacing:1.5px;text-transform:uppercase;opacity:.82">
              Invoice Integrity Report
            </div>
            <h1 style="margin:8px 0 0;font-size:28px">{escape(str(invoice["test_number"]))}</h1>
          </div>
          <div style="background:white;padding:28px;border-radius:0 0 16px 16px">
            <div style="display:inline-block;padding:8px 13px;border-radius:999px;
                        color:white;background:{colors.get(verdict, "#68756b")};font-weight:bold">
              {escape(verdict_labels.get(verdict, verdict))}
            </div>
            <div style="font-size:42px;font-weight:800;margin-top:18px">
              {int(invoice["risk_score"])}
              <span style="font-size:17px;color:#68756b">/100 risk</span>
            </div>
            <p style="line-height:1.6;color:#4f6055">{escape(str(invoice["summary"]))}</p>
            <table style="width:100%;border-collapse:collapse;margin-top:22px">
              <thead>
                <tr style="background:#edf7f0;text-align:left">
                  <th style="padding:12px">Test and evidence</th>
                  <th style="padding:12px">Status</th>
                  <th style="padding:12px">Was this right?</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
            <div style="text-align:center;margin:28px 0">
              <a href="{settings.public_base_url}/invoices/{int(invoice["id"])}"
                 style="background:#0b5f3c;color:white;text-decoration:none;
                        padding:13px 22px;border-radius:9px;font-weight:bold">
                Review full report
              </a>
            </div>
            <p style="font-size:12px;line-height:1.5;color:#77837b">
              Automated analysis is decision support, not proof of authenticity. Confirm high-risk
              invoices against the original source, GST/IRP records, vendor master, purchase order,
              goods receipt and independently verified payment details.
            </p>
          </div>
        </div>
      </body>
    </html>
    """


async def send_report(invoice: sqlite3.Row, tests: list[sqlite3.Row], recipient: str) -> bool:
    if not settings.smtp_host or not settings.smtp_from_email:
        return False
    message = EmailMessage()
    message["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
    message["To"] = recipient
    message["Subject"] = f"Invoice review {invoice['test_number']}: {invoice['verdict']}"
    message.set_content(
        f"Invoice review {invoice['test_number']}: {invoice['summary']}\n"
        f"Open {settings.public_base_url}/invoices/{invoice['id']}"
    )
    message.add_alternative(render_report_email(invoice, tests), subtype="html")
    await aiosmtplib.send(
        message,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username or None,
        password=settings.smtp_password or None,
        start_tls=settings.smtp_use_tls,
    )
    return True
