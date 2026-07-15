import os
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def _as_bool(value: str, default: bool) -> bool:
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(os.getenv("DATA_DIR", ROOT_DIR / "data"))
    upload_dir: Path = Path(os.getenv("UPLOAD_DIR", ROOT_DIR / "uploads"))
    app_secret: str = os.getenv("APP_SECRET", "local-development-only-change-me")
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")
    session_hours: int = int(os.getenv("SESSION_HOURS", "12"))
    feedback_link_days: int = int(os.getenv("FEEDBACK_LINK_DAYS", "7"))
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "20"))
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from_email: str = os.getenv("SMTP_FROM_EMAIL", "")
    smtp_from_name: str = os.getenv("SMTP_FROM_NAME", "Invoice Integrity")
    smtp_use_tls: bool = _as_bool(os.getenv("SMTP_USE_TLS", "true"), True)

    @property
    def database_path(self) -> Path:
        return self.data_dir / "invoice_authenticator.db"


settings = Settings()
