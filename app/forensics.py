import re
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import cv2
import fitz  # type: ignore[import-untyped]
import numpy as np
import pytesseract  # type: ignore[import-untyped]
from PIL import Image, ImageChops, ImageStat

from app.database import find_comparison_candidates, find_exact_duplicates

GSTIN_PATTERN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
INVOICE_PATTERNS = (
    re.compile(
        r"(?:invoice|bill)\s*(?:number|no\.?|#)\s*[:\-]?\s*([A-Z0-9][A-Z0-9\-/]{2,})",
        re.IGNORECASE,
    ),
    re.compile(r"\binv(?:oice)?[-/\s]*([A-Z0-9][A-Z0-9\-/]{2,})\b", re.IGNORECASE),
)
DATE_PATTERN = re.compile(
    r"(?:invoice\s*date|date)\s*[:\-]?\s*(\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})",
    re.IGNORECASE,
)
AMOUNT_PATTERN = re.compile(
    r"(?:grand\s*total|invoice\s*total|amount\s*due|total)\s*[:₹$INR\s]*"
    r"([0-9][0-9,]*(?:\.\d{1,2})?)",
    re.IGNORECASE,
)
SUSPICIOUS_EDITORS = ("photoshop", "gimp", "canva", "illustrator", "photopea", "inkscape")


@dataclass(frozen=True)
class ExtractedFields:
    invoice_number: str | None
    invoice_date: str | None
    amount: str | None
    gstin: str | None


@dataclass(frozen=True)
class Analysis:
    sha256: str
    perceptual_hash: str | None
    fields: ExtractedFields
    verdict: str
    risk_score: int
    summary: str
    tests: list[dict[str, object]]


def _test(
    key: str,
    name: str,
    category: str,
    status: str,
    severity: str,
    confidence: int,
    evidence: str,
    recommendation: str,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "key": key,
        "name": name,
        "category": category,
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": recommendation,
        "metadata": metadata or {},
    }


def hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _render_document(path: Path, mime_type: str) -> tuple[Image.Image, str, dict[str, str]]:
    metadata: dict[str, str] = {}
    if mime_type == "application/pdf" or path.suffix.lower() == ".pdf":
        document = fitz.open(path)
        if document.page_count < 1:
            document.close()
            raise ValueError("PDF contains no pages")
        metadata = {key: value or "" for key, value in document.metadata.items()}
        page = document.load_page(0)
        pixmap = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
        image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
        text = "\n".join(
            document.load_page(index).get_text() for index in range(document.page_count)
        )
        if len(text.strip()) < 40:
            text = pytesseract.image_to_string(image)
        document.close()
        return image, text, metadata
    image = Image.open(path).convert("RGB")
    return image, pytesseract.image_to_string(image), metadata


def _difference_hash(image: Image.Image) -> str:
    grayscale = image.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    pixels = np.asarray(grayscale)
    bits = pixels[:, 1:] > pixels[:, :-1]
    value = 0
    for bit in bits.flatten():
        value = (value << 1) | int(bit)
    return f"{value:016x}"


def _hamming_distance(first: str, second: str) -> int:
    return (int(first, 16) ^ int(second, 16)).bit_count()


def _gstin_checksum_valid(gstin: str) -> bool:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    factor = 1
    total = 0
    for character in gstin[:-1]:
        code_point = alphabet.index(character)
        product = code_point * factor
        factor = 1 if factor == 2 else 2
        total += (product // 36) + (product % 36)
    check_code_point = (36 - (total % 36)) % 36
    return alphabet[check_code_point] == gstin[-1]


def _extract_fields(text: str) -> ExtractedFields:
    compact = " ".join(text.split())
    invoice_number = None
    for pattern in INVOICE_PATTERNS:
        match = pattern.search(compact)
        if match:
            invoice_number = match.group(1).strip(" .:-")
            break
    date_match = DATE_PATTERN.search(compact)
    amount_matches = list(AMOUNT_PATTERN.finditer(compact))
    gstin_match = GSTIN_PATTERN.search(compact.upper())
    return ExtractedFields(
        invoice_number=invoice_number,
        invoice_date=date_match.group(1) if date_match else None,
        amount=amount_matches[-1].group(1) if amount_matches else None,
        gstin=gstin_match.group(0) if gstin_match else None,
    )


def _ela_score(image: Image.Image) -> float:
    source = image.convert("RGB")
    recompressed = BytesIO()
    source.save(recompressed, "JPEG", quality=90)
    recompressed.seek(0)
    difference = ImageChops.difference(source, Image.open(recompressed).convert("RGB"))
    return float(sum(ImageStat.Stat(difference).mean) / 3)


def _qr_payload(image: Image.Image) -> str:
    array = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
    payload, _, _ = cv2.QRCodeDetector().detectAndDecode(array)
    return payload.strip()


def _numeric_tokens(text: str) -> set[str]:
    return {
        token.lstrip("0") or "0"
        for token in re.findall(r"\b\d[\d,.]*\b", text)
        if len(re.sub(r"\D", "", token)) >= 2
    }


def _text_layer_consistency(text_layer: str, ocr_text: str) -> tuple[float, int]:
    text_numbers = _numeric_tokens(text_layer)
    ocr_numbers = _numeric_tokens(ocr_text)
    union = text_numbers | ocr_numbers
    if not union:
        return 1.0, 0
    return len(text_numbers & ocr_numbers) / len(union), len(union)


def _calculate_verdict(
    tests: list[dict[str, object]],
) -> tuple[str, int, str]:
    weights = {"critical": 50, "high": 30, "medium": 15, "low": 5}
    risk = 0
    failed_keys: set[str] = set()
    failed_categories: set[str] = set()
    for result in tests:
        status = str(result["status"])
        severity = str(result["severity"])
        if status == "fail":
            risk += weights[severity]
            failed_keys.add(str(result["key"]))
            failed_categories.add(str(result["category"]))
        elif status == "warning":
            risk += max(3, weights[severity] // 2)
    risk_score = min(100, risk)

    strong_tamper_signal = "near_duplicate_changed_fields" in failed_keys
    corroborated_high_failures = len(failed_categories) >= 2 and sum(
        result["status"] == "fail"
        and result["severity"] in {"critical", "high"}
        and result["key"] not in {"exact_duplicate", "invoice_number_duplicate"}
        for result in tests
    ) >= 2

    if strong_tamper_signal or corroborated_high_failures:
        return (
            "likely_tampered",
            risk_score,
            "Corroborating evidence indicates altered or unreliable invoice content.",
        )
    if risk_score >= 25 or failed_keys:
        return (
            "needs_review",
            risk_score,
            "Material anomalies or verification gaps require independent human review.",
        )
    return (
        "likely_genuine",
        risk_score,
        "No strong anomaly was found, but source and business-record verification "
        "is still required.",
    )


def analyze_invoice(
    path: Path,
    *,
    mime_type: str,
    invoice_id: int,
    sender_name: str,
    sender_email: str,
) -> Analysis:
    tests: list[dict[str, object]] = []
    file_hash = hash_file(path)
    duplicates = find_exact_duplicates(file_hash, invoice_id)
    tests.append(
        _test(
            "exact_duplicate",
            "Exact duplicate file",
            "Duplicate detection",
            "fail" if duplicates else "pass",
            "high",
            100,
            (
                f"Identical SHA-256 content already exists as {duplicates[0]['test_number']}."
                if duplicates
                else "No byte-identical prior upload was found."
            ),
            (
                "Confirm whether this is an intentional re-upload before processing."
                if duplicates
                else "Continue with near-duplicate and content checks."
            ),
            {"matches": [row["test_number"] for row in duplicates]},
        )
    )

    try:
        image, text, metadata = _render_document(path, mime_type)
        tests.append(
            _test(
                "file_readability",
                "File structure and readability",
                "File integrity",
                "pass",
                "high",
                100,
                "The document opened and its first page rendered successfully.",
                "No action required.",
            )
        )
    except (fitz.FileDataError, OSError, ValueError) as error:
        tests.append(
            _test(
                "file_readability",
                "File structure and readability",
                "File integrity",
                "fail",
                "critical",
                100,
                f"The document could not be parsed safely: {error}.",
                "Obtain a fresh original directly from the sender.",
            )
        )
        verdict, risk_score, summary = _calculate_verdict(tests)
        return Analysis(
            sha256=file_hash,
            perceptual_hash=None,
            fields=ExtractedFields(None, None, None, None),
            verdict=verdict,
            risk_score=risk_score,
            summary=summary,
            tests=tests,
        )

    perceptual_hash = _difference_hash(image)
    candidates = find_comparison_candidates(invoice_id)
    near_matches = [
        row
        for row in candidates
        if row["perceptual_hash"]
        and _hamming_distance(perceptual_hash, str(row["perceptual_hash"])) <= 5
    ]
    tests.append(
        _test(
            "near_duplicate",
            "Near-duplicate appearance",
            "Duplicate detection",
            "warning" if near_matches else "pass",
            "medium",
            82 if near_matches else 75,
            (
                f"Visually similar to {near_matches[0]['test_number']}."
                if near_matches
                else "No very close first-page visual fingerprint was found."
            ),
            (
                "Compare the invoices side by side, especially identifiers, totals "
                "and bank details."
                if near_matches
                else "No action required."
            ),
            {"matches": [row["test_number"] for row in near_matches[:10]]},
        )
    )

    if path.suffix.lower() == ".pdf" or mime_type == "application/pdf":
        raw_pdf = path.read_bytes()
        revisions = raw_pdf.count(b"startxref")
        eof_markers = raw_pdf.count(b"%%EOF")
        tests.append(
            _test(
                "pdf_revisions",
                "PDF revision history",
                "File integrity",
                "warning" if revisions > 1 or eof_markers > 1 else "pass",
                "low",
                85,
                (
                    f"Found {revisions} cross-reference revision(s) and "
                    f"{eof_markers} EOF marker(s)."
                ),
                (
                    "Review whether edits were expected; incremental revisions are "
                    "not proof of fraud."
                    if revisions > 1 or eof_markers > 1
                    else "No incremental update signal was found."
                ),
                {"revisions": revisions, "eof_markers": eof_markers},
            )
        )
        document = fitz.open(path)
        signature_flags = int(document.get_sigflags())
        has_signature = signature_flags > 0
        document.close()
        tests.append(
            _test(
                "digital_signature",
                "PDF digital signature",
                "Cryptographic provenance",
                "not_run",
                "high",
                60 if has_signature else 100,
                (
                    "The PDF declares a signature field, but this local test does not "
                    "validate its certificate chain or signed revision."
                    if has_signature
                    else "No PDF digital signature was present to validate."
                ),
                (
                    "Validate the certificate chain, timestamp, revocation and signed revision."
                    if has_signature
                    else "Ask high-risk vendors to issue digitally signed originals."
                ),
                {"signature_flags": signature_flags},
            )
        )
        active_markers = {
            marker.decode(): raw_pdf.count(marker)
            for marker in (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile")
            if raw_pdf.count(marker)
        }
        tests.append(
            _test(
                "pdf_active_content",
                "PDF active or embedded content",
                "File integrity",
                "warning" if active_markers else "pass",
                "medium",
                90,
                (
                    "Potential active or embedded PDF objects were found: "
                    + ", ".join(active_markers)
                    if active_markers
                    else "No common JavaScript, launch-action or embedded-file marker was found."
                ),
                (
                    "Open only in a hardened viewer and inspect embedded objects."
                    if active_markers
                    else "No action required."
                ),
                {"markers": active_markers},
            )
        )
        metadata_text = " ".join(metadata.values()).lower()
        matched_editors = [editor for editor in SUSPICIOUS_EDITORS if editor in metadata_text]
        created = metadata.get("creationDate", "")
        modified = metadata.get("modDate", "")
        metadata_warning = bool(matched_editors) or (created and modified and created != modified)
        tests.append(
            _test(
                "pdf_metadata",
                "PDF metadata consistency",
                "File integrity",
                "warning" if metadata_warning else "pass",
                "low",
                65,
                (
                    "Potential editing signal: " + ", ".join(matched_editors)
                    if matched_editors
                    else (
                        "Creation and modification metadata differ."
                        if created and modified and created != modified
                        else "No obvious editor or timestamp conflict was found."
                    )
                ),
                "Treat metadata as supporting evidence only; it can be missing or rewritten.",
                {"metadata": metadata},
            )
        )
    else:
        tests.extend(
            [
                _test(
                    "pdf_revisions",
                    "PDF revision history",
                    "File integrity",
                    "not_run",
                    "low",
                    100,
                    "The uploaded document is not a PDF.",
                    "Upload the original PDF when available.",
                ),
                _test(
                    "digital_signature",
                    "PDF digital signature",
                    "Cryptographic provenance",
                    "not_run",
                    "high",
                    100,
                    "The uploaded document is not a signed PDF.",
                    "Request a digitally signed source invoice for high-value payments.",
                ),
                _test(
                    "pdf_active_content",
                    "PDF active or embedded content",
                    "File integrity",
                    "not_run",
                    "medium",
                    100,
                    "The uploaded document is not a PDF.",
                    "No action required.",
                ),
            ]
        )

    fields = _extract_fields(text)
    tests.append(
        _test(
            "text_extraction",
            "Machine-readable invoice content",
            "Content validation",
            "pass" if len(text.strip()) >= 40 else "warning",
            "medium",
            90,
            (
                f"Extracted {len(text.strip())} machine-readable characters."
                if text.strip()
                else "No machine-readable text layer was found."
            ),
            (
                "Run OCR or obtain a digital original before relying on field checks."
                if len(text.strip()) < 40
                else "Review extracted values below."
            ),
        )
    )
    tests.append(
        _test(
            "invoice_number",
            "Invoice number extraction",
            "Content validation",
            "pass" if fields.invoice_number else "warning",
            "medium",
            80,
            (
                f"Invoice number extracted as {fields.invoice_number}."
                if fields.invoice_number
                else "An invoice number could not be extracted confidently."
            ),
            (
                "Confirm the invoice number manually."
                if not fields.invoice_number
                else "No action required."
            ),
        )
    )

    if fields.gstin:
        gstin_valid = _gstin_checksum_valid(fields.gstin)
        tests.append(
            _test(
                "gstin",
                "GSTIN structure and checksum",
                "India GST",
                "pass" if gstin_valid else "fail",
                "high",
                100,
                (
                    f"GSTIN {fields.gstin} has a valid checksum."
                    if gstin_valid
                    else f"GSTIN {fields.gstin} has an invalid checksum."
                ),
                (
                    "Verify the GSTIN's legal name and status on the official GST portal."
                    if gstin_valid
                    else "Do not approve until the supplier identity is independently verified."
                ),
            )
        )
    else:
        tests.append(
            _test(
                "gstin",
                "GSTIN structure and checksum",
                "India GST",
                "not_run",
                "high",
                80,
                "No GSTIN was extracted from the machine-readable text.",
                "Enter or verify the GSTIN manually and check the official GST portal.",
            )
        )

    if path.suffix.lower() == ".pdf" or mime_type == "application/pdf":
        ocr_text = pytesseract.image_to_string(image)
        consistency, token_count = _text_layer_consistency(text, ocr_text)
        mismatch = token_count >= 4 and consistency < 0.45
        tests.append(
            _test(
                "visible_text_consistency",
                "Visible text versus PDF text layer",
                "Content validation",
                "warning" if mismatch else "pass",
                "medium",
                70,
                (
                    f"Numeric-token agreement was {consistency:.0%} across "
                    f"{token_count} distinct values."
                    if token_count
                    else "There were too few numeric tokens for a meaningful comparison."
                ),
                (
                    "Compare visible totals, dates, tax IDs and bank details with extracted text."
                    if mismatch
                    else "No strong hidden-text mismatch was found."
                ),
                {"agreement": round(consistency, 3), "numeric_tokens": token_count},
            )
        )
    else:
        tests.append(
            _test(
                "visible_text_consistency",
                "Visible text versus PDF text layer",
                "Content validation",
                "not_run",
                "medium",
                100,
                "Image uploads do not contain a separate PDF text layer.",
                "No action required.",
            )
        )

    qr_payload = _qr_payload(image)
    tests.append(
        _test(
            "qr_payload",
            "Invoice QR payload",
            "India GST",
            "not_run",
            "high",
            60 if qr_payload else 85,
            (
                f"A QR payload was decoded ({len(qr_payload)} characters), but its "
                "IRP signature has not yet been validated."
                if qr_payload
                else "No readable QR code was found on the first page."
            ),
            (
                "Compare signed QR/IRN fields with the visible invoice and validate "
                "the IRP signature."
                if qr_payload
                else "Confirm whether this supplier is required to issue a GST e-invoice."
            ),
            {"payload_preview": qr_payload[:120]},
        )
    )

    ela = _ela_score(image)
    visual_status = "warning" if ela >= 8.0 else "pass"
    tests.append(
        _test(
            "compression_consistency",
            "Visual compression consistency",
            "Visual forensics",
            visual_status,
            "low",
            55,
            f"First-page recompression difference score: {ela:.2f}.",
            (
                "Inspect the original-resolution file and compare suspicious regions manually."
                if visual_status == "warning"
                else "This weak signal found no broad compression anomaly."
            ),
            {"ela_score": round(ela, 3)},
        )
    )

    sender_complete = bool(sender_name or sender_email)
    tests.append(
        _test(
            "sender_traceability",
            "Sender traceability",
            "Business verification",
            "pass" if sender_complete else "warning",
            "medium",
            100,
            (
                f"Sender recorded as {sender_name or sender_email}."
                if sender_complete
                else "No sender identity was recorded with the upload."
            ),
            (
                "Independently verify unusual requests using known vendor contact details."
                if sender_complete
                else "Record who supplied the invoice before approval."
            ),
        )
    )

    if fields.invoice_number:
        normalized_number = re.sub(r"[^A-Z0-9]", "", fields.invoice_number.upper())
        semantic_matches = [
            row
            for row in candidates
            if row["invoice_number"]
            and re.sub(r"[^A-Z0-9]", "", str(row["invoice_number"]).upper())
            == normalized_number
        ]
        tests.append(
            _test(
                "invoice_number_duplicate",
                "Duplicate invoice number",
                "Duplicate detection",
                "fail" if semantic_matches else "pass",
                "high",
                95,
                (
                    f"The invoice number matches {semantic_matches[0]['test_number']}."
                    if semantic_matches
                    else "No prior normalized invoice-number match was found."
                ),
                (
                    "Confirm credit-note, revision or reissue status before approval."
                    if semantic_matches
                    else "No action required."
                ),
                {"matches": [row["test_number"] for row in semantic_matches[:10]]},
            )
        )
    else:
        tests.append(
            _test(
                "invoice_number_duplicate",
                "Duplicate invoice number",
                "Duplicate detection",
                "not_run",
                "high",
                100,
                "Invoice-number matching could not run without an extracted number.",
                "Enter the invoice number manually and rerun the review.",
            )
        )

    changed_matches: list[str] = []
    if near_matches:
        for row in near_matches:
            differing_fields = [
                name
                for name, current, previous in (
                    ("invoice number", fields.invoice_number, row["invoice_number"]),
                    ("amount", fields.amount, row["amount"]),
                    ("GSTIN", fields.gstin, row["gstin"]),
                )
                if current and previous and str(current) != str(previous)
            ]
            if differing_fields:
                changed_matches.append(
                    f"{row['test_number']} ({', '.join(differing_fields)} changed)"
                )
    tests.append(
        _test(
            "near_duplicate_changed_fields",
            "Near-duplicate with changed key fields",
            "Visual forensics",
            "fail" if changed_matches else "pass",
            "high",
            88 if changed_matches else 70,
            (
                "Similar prior invoice(s) contain different key values: "
                + "; ".join(changed_matches[:5])
                if changed_matches
                else "No close visual match with conflicting extracted key fields was found."
            ),
            (
                "Obtain both originals from the vendor and compare altered regions before approval."
                if changed_matches
                else "No action required."
            ),
            {"matches": changed_matches},
        )
    )

    verdict, risk_score, summary = _calculate_verdict(tests)

    return Analysis(
        sha256=file_hash,
        perceptual_hash=perceptual_hash,
        fields=fields,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        tests=tests,
    )
