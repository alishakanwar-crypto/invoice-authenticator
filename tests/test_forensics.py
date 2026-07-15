from datetime import datetime, timedelta

from app.config import IST
from app.database import ist_now
from app.email_service import feedback_token, verify_feedback_token
from app.forensics import _calculate_verdict, _gstin_checksum_valid, _hamming_distance


def test_gstin_checksum_accepts_known_valid_value() -> None:
    assert _gstin_checksum_valid("27AAPFU0939F1ZV")


def test_gstin_checksum_rejects_changed_check_digit() -> None:
    assert not _gstin_checksum_valid("27AAPFU0939F1ZW")


def test_hamming_distance() -> None:
    assert _hamming_distance("0000000000000000", "000000000000000f") == 4


def test_duplicate_only_requires_review_instead_of_claiming_tampering() -> None:
    verdict, risk, _ = _calculate_verdict(
        [
            {
                "key": "exact_duplicate",
                "category": "Duplicate detection",
                "status": "fail",
                "severity": "high",
            },
            {
                "key": "invoice_number_duplicate",
                "category": "Duplicate detection",
                "status": "fail",
                "severity": "high",
            },
        ]
    )
    assert verdict == "needs_review"
    assert risk == 60


def test_changed_fields_in_near_duplicate_is_strong_tamper_signal() -> None:
    verdict, _, _ = _calculate_verdict(
        [
            {
                "key": "near_duplicate_changed_fields",
                "category": "Visual forensics",
                "status": "fail",
                "severity": "high",
            }
        ]
    )
    assert verdict == "likely_tampered"


def test_feedback_token_expires() -> None:
    now = int(datetime.now(IST).timestamp())
    active_token = feedback_token(1, 2, "correct", now + 60)
    expired_token = feedback_token(1, 2, "correct", now - 60)

    assert verify_feedback_token(1, 2, "correct", now + 60, active_token)
    assert not verify_feedback_token(1, 2, "correct", now - 60, expired_token)


def test_database_timestamps_use_ist() -> None:
    timestamp = datetime.fromisoformat(ist_now())

    assert timestamp.utcoffset() == timedelta(hours=5, minutes=30)
