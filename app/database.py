import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import cast

from app.config import IST, settings


def ist_now() -> str:
    return datetime.now(IST).isoformat()


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    database = sqlite3.connect(settings.database_path)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys = ON")
    try:
        yield database
        database.commit()
    finally:
        database.close()


def initialize_database() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    with connection() as database:
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_number TEXT UNIQUE,
                original_filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                perceptual_hash TEXT,
                sender_name TEXT,
                sender_email TEXT,
                report_email TEXT,
                vendor_name TEXT,
                notes TEXT,
                invoice_number TEXT,
                invoice_date TEXT,
                amount TEXT,
                gstin TEXT,
                verdict TEXT NOT NULL DEFAULT 'processing',
                risk_score INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                analyzed_at TEXT,
                report_sent_at TEXT,
                manual_verdict TEXT,
                manual_notes TEXT
            );

            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
                test_key TEXT NOT NULL,
                test_name TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(invoice_id, test_key)
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
                test_result_id INTEGER REFERENCES test_results(id) ON DELETE CASCADE,
                response TEXT NOT NULL,
                explanation TEXT,
                reviewer_name TEXT,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS used_feedback_tokens (
                token_digest TEXT PRIMARY KEY,
                used_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_invoices_sha256 ON invoices(sha256);
            CREATE INDEX IF NOT EXISTS idx_invoices_number ON invoices(invoice_number);
            CREATE INDEX IF NOT EXISTS idx_invoices_created_at ON invoices(created_at DESC);
            """
        )


def create_invoice(
    *,
    original_filename: str,
    stored_path: Path,
    mime_type: str,
    file_size: int,
    sha256: str,
    sender_name: str,
    sender_email: str,
    report_email: str,
    vendor_name: str,
    notes: str,
) -> int:
    created_at = ist_now()
    with connection() as database:
        cursor = database.execute(
            """
            INSERT INTO invoices (
                test_number, original_filename, stored_path, mime_type, file_size,
                sha256, sender_name, sender_email, report_email, vendor_name, notes,
                created_at
            ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                original_filename,
                str(stored_path),
                mime_type,
                file_size,
                sha256,
                sender_name or None,
                sender_email or None,
                report_email or None,
                vendor_name or None,
                notes or None,
                created_at,
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("Invoice record was not created")
        invoice_id = cursor.lastrowid
        date_part = datetime.now(IST).strftime("%Y%m%d")
        test_number = f"IV-{date_part}-{invoice_id:06d}"
        database.execute(
            "UPDATE invoices SET test_number = ? WHERE id = ?",
            (test_number, invoice_id),
        )
    return invoice_id


def update_invoice_analysis(
    invoice_id: int,
    *,
    perceptual_hash: str | None,
    invoice_number: str | None,
    invoice_date: str | None,
    amount: str | None,
    gstin: str | None,
    verdict: str,
    risk_score: int,
    summary: str,
) -> None:
    with connection() as database:
        database.execute(
            """
            UPDATE invoices
            SET perceptual_hash = ?, invoice_number = ?, invoice_date = ?, amount = ?,
                gstin = ?, verdict = ?, risk_score = ?, summary = ?, analyzed_at = ?
            WHERE id = ?
            """,
            (
                perceptual_hash,
                invoice_number,
                invoice_date,
                amount,
                gstin,
                verdict,
                risk_score,
                summary,
                ist_now(),
                invoice_id,
            ),
        )


def save_test_results(invoice_id: int, tests: list[dict[str, object]]) -> None:
    with connection() as database:
        database.execute("DELETE FROM test_results WHERE invoice_id = ?", (invoice_id,))
        for result in tests:
            database.execute(
                """
                INSERT INTO test_results (
                    invoice_id, test_key, test_name, category, status, severity,
                    confidence, evidence, recommendation, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invoice_id,
                    result["key"],
                    result["name"],
                    result["category"],
                    result["status"],
                    result["severity"],
                    result["confidence"],
                    result["evidence"],
                    result["recommendation"],
                    json.dumps(result.get("metadata", {})),
                    ist_now(),
                ),
            )


def list_invoices(
    *, search: str = "", verdict: str = "", limit: int = 100
) -> list[sqlite3.Row]:
    clauses: list[str] = []
    parameters: list[object] = []
    if search:
        clauses.append(
            """
            (
                test_number LIKE ? OR original_filename LIKE ? OR vendor_name LIKE ?
                OR sender_name LIKE ? OR invoice_number LIKE ?
            )
            """
        )
        pattern = f"%{search}%"
        parameters.extend([pattern] * 5)
    if verdict:
        clauses.append("verdict = ?")
        parameters.append(verdict)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    with connection() as database:
        return list(
            database.execute(
                f"SELECT * FROM invoices {where} ORDER BY id DESC LIMIT ?",  # noqa: S608
                parameters,
            ).fetchall()
        )


def get_invoice(invoice_id: int) -> sqlite3.Row | None:
    with connection() as database:
        row = database.execute(
            "SELECT * FROM invoices WHERE id = ?",
            (invoice_id,),
        ).fetchone()
        return cast(sqlite3.Row | None, row)


def get_test_results(invoice_id: int) -> list[sqlite3.Row]:
    with connection() as database:
        return list(
            database.execute(
                """
                SELECT test_results.*,
                       (
                           SELECT response FROM feedback
                           WHERE feedback.test_result_id = test_results.id
                           ORDER BY feedback.id DESC LIMIT 1
                       ) AS latest_feedback
                FROM test_results
                WHERE invoice_id = ?
                ORDER BY
                    CASE status WHEN 'fail' THEN 1 WHEN 'warning' THEN 2
                                WHEN 'pass' THEN 3 ELSE 4 END,
                    id
                """,
                (invoice_id,),
            ).fetchall()
        )


def find_exact_duplicates(sha256: str, exclude_invoice_id: int) -> list[sqlite3.Row]:
    with connection() as database:
        return list(
            database.execute(
                """
                SELECT id, test_number, original_filename, created_at
                FROM invoices WHERE sha256 = ? AND id != ?
                ORDER BY id DESC
                """,
                (sha256, exclude_invoice_id),
            ).fetchall()
        )


def find_comparison_candidates(exclude_invoice_id: int) -> list[sqlite3.Row]:
    with connection() as database:
        return list(
            database.execute(
                """
                SELECT id, test_number, perceptual_hash, invoice_number, vendor_name,
                       amount, gstin
                FROM invoices
                WHERE id != ? AND analyzed_at IS NOT NULL
                ORDER BY id DESC LIMIT 500
                """,
                (exclude_invoice_id,),
            ).fetchall()
        )


def add_feedback(
    *,
    invoice_id: int,
    test_result_id: int | None,
    response: str,
    explanation: str,
    reviewer_name: str,
    source: str,
) -> None:
    with connection() as database:
        database.execute(
            """
            INSERT INTO feedback (
                invoice_id, test_result_id, response, explanation,
                reviewer_name, source, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invoice_id,
                test_result_id,
                response,
                explanation or None,
                reviewer_name or None,
                source,
                ist_now(),
            ),
        )


def consume_feedback_token(token_digest: str) -> bool:
    with connection() as database:
        cursor = database.execute(
            """
            INSERT OR IGNORE INTO used_feedback_tokens (token_digest, used_at)
            VALUES (?, ?)
            """,
            (token_digest, ist_now()),
        )
        return cursor.rowcount == 1


def update_manual_review(invoice_id: int, verdict: str, notes: str) -> None:
    with connection() as database:
        database.execute(
            "UPDATE invoices SET manual_verdict = ?, manual_notes = ? WHERE id = ?",
            (verdict or None, notes or None, invoice_id),
        )


def mark_report_sent(invoice_id: int) -> None:
    with connection() as database:
        database.execute(
            "UPDATE invoices SET report_sent_at = ? WHERE id = ?",
            (ist_now(), invoice_id),
        )
