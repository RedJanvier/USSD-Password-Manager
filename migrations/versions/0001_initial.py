"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type():
    return sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("msisdn", sa.String(20), primary_key=True),
        sa.Column("pin_verifier", sa.Text(), nullable=False),
        sa.Column("pin_salt", sa.LargeBinary(), nullable=False),
        sa.Column("rec_salt", sa.LargeBinary(), nullable=False),
        sa.Column("dek_wrapped_pin", sa.LargeBinary(), nullable=False),
        sa.Column("dek_wrapped_pin_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("dek_wrapped_rec", sa.LargeBinary(), nullable=False),
        sa.Column("dek_wrapped_rec_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("recovery_verifier", sa.Text(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "vault_entries",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "msisdn",
            sa.String(20),
            sa.ForeignKey("users.msisdn", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("site_name", sa.String(120), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("msisdn", "site_name", name="uq_vault_msisdn_site"),
    )

    op.create_table(
        "recovery_tokens",
        sa.Column(
            "msisdn",
            sa.String(20),
            sa.ForeignKey("users.msisdn", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "ussd_sessions",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("msisdn", sa.String(20), nullable=False),
        sa.Column("state", _json_type(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("msisdn", sa.String(20), index=True),
        sa.Column("event", sa.String(40), nullable=False),
        sa.Column("site_name", sa.String(120)),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("ussd_sessions")
    op.drop_table("recovery_tokens")
    op.drop_table("vault_entries")
    op.drop_table("users")
