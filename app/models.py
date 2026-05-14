from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db import Base


# Use JSONB on Postgres, JSON elsewhere (SQLite for dev). This way the same models
# work in both environments without conditional code at call sites.
JSONType = JSON().with_variant(JSONB(), "postgresql")
# Integer on SQLite (which autoincrements it as ROWID), BigInteger on Postgres
# (where we want the 64-bit range for high-volume tables).
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class User(Base):
    __tablename__ = "users"

    msisdn: Mapped[str] = mapped_column(String(20), primary_key=True)
    pin_verifier: Mapped[str] = mapped_column(Text, nullable=False)
    pin_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    rec_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_wrapped_pin: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_wrapped_pin_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_wrapped_rec: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_wrapped_rec_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    recovery_verifier: Mapped[str] = mapped_column(Text, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class VaultEntry(Base):
    __tablename__ = "vault_entries"
    __table_args__ = (UniqueConstraint("msisdn", "site_name", name="uq_vault_msisdn_site"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    msisdn: Mapped[str] = mapped_column(
        String(20), ForeignKey("users.msisdn", ondelete="CASCADE"), nullable=False, index=True
    )
    site_name: Mapped[str] = mapped_column(String(120), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class RecoveryToken(Base):
    """Short-lived SMS recovery code. One per user; replaced on each request."""

    __tablename__ = "recovery_tokens"

    msisdn: Mapped[str] = mapped_column(
        String(20), ForeignKey("users.msisdn", ondelete="CASCADE"), primary_key=True
    )
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class UssdSession(Base):
    """Server-side session state keyed by Africa's Talking sessionId.

    AT enforces 180s session timeout; we expire rows after 300s to give a small
    grace window. We never split the AT `text` field by `*` to recover state —
    user-supplied passwords legitimately contain `*`.
    """

    __tablename__ = "ussd_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    msisdn: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    """Append-only event log. Never stores PINs, ciphertexts, or plaintext."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    msisdn: Mapped[str | None] = mapped_column(String(20), index=True)
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    site_name: Mapped[str | None] = mapped_column(String(120))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
