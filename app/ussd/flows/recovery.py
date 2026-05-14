"""Recovery flow — two factors required.

* Menu 4 — request: server generates a one-time SMS code, stores its Argon2
  hash with a 15-min TTL, and SMSes the plaintext.
* Menu 5 — redeem: user supplies (sms_code, new_pin, long_term_recovery_code).
  The SMS code is a proof-of-phone-possession check; the long-term recovery
  code (issued at registration) is what actually unwraps the DEK.

If the user has lost both their PIN *and* their long-term recovery code, the
vault is unrecoverable by design — that's the zero-knowledge property.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.audit import log as audit_log
from app.config import get_settings
from app.models import RecoveryToken
from app.sms import send_recovery_code
from app.timeutil import aware, now
from app.ussd.flows._common import find_user, valid_pin
from app.ussd.responses import con, end

SMS_CODE_TTL = timedelta(minutes=15)
SMS_CODE_LEN = 8
SMS_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MAX_SMS_CODE_ATTEMPTS = 3


def _gen_sms_code() -> str:
    return "".join(secrets.choice(SMS_CODE_ALPHABET) for _ in range(SMS_CODE_LEN))


# ─── 4: Request recovery code ───────────────────────────────────────────────

async def request_handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    user = await find_user(db, msisdn)
    if user is None:
        return end("No vault on this number.")

    pepper = get_settings().pepper_bytes
    # We can't unwrap the DEK here (no PIN, no long-term code), so we don't
    # touch the recovery wrap. We just issue a short-lived SMS token that
    # proves possession of the phone at redeem time.
    sms_code = _gen_sms_code()
    code_hash = crypto._PIN_VERIFIER_HASHER.hash(sms_code + ":" + pepper.hex())

    await db.execute(delete(RecoveryToken).where(RecoveryToken.msisdn == msisdn))
    db.add(
        RecoveryToken(
            msisdn=msisdn,
            code_hash=code_hash,
            expires_at=now() + SMS_CODE_TTL,
            attempts=0,
        )
    )
    await db.commit()
    send_recovery_code(msisdn, sms_code)
    await audit_log(db, msisdn=msisdn, event="recovery_request", success=True)
    return end("Recovery code sent by SMS. Dial again, choose 5, then enter it.")


# ─── 5: Redeem recovery code ────────────────────────────────────────────────

async def redeem_handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    """Redeem an SMS code: 5*<sms_code>*<new_pin>*<long_term_recovery_code>."""
    pepper = get_settings().pepper_bytes
    user = await find_user(db, msisdn)
    if user is None:
        return end("No vault on this number.")

    if len(inputs) == 0:
        return con("SMS code (from menu option 4)?")
    sms_code = inputs[0].strip().upper()

    token = (
        await db.execute(select(RecoveryToken).where(RecoveryToken.msisdn == msisdn))
    ).scalar_one_or_none()
    if token is None or aware(token.expires_at) < now():
        return end("No active recovery code. Dial again, choose 4.")
    if token.attempts >= MAX_SMS_CODE_ATTEMPTS:
        return end("Too many wrong SMS codes. Dial again, choose 4.")
    try:
        crypto._PIN_VERIFIER_HASHER.verify(token.code_hash, sms_code + ":" + pepper.hex())
    except Exception:
        token.attempts += 1
        await db.commit()
        await audit_log(db, msisdn=msisdn, event="recovery_wrong_sms", success=False)
        return end("Wrong SMS code.")

    if len(inputs) == 1:
        return con("New 4-8 digit PIN?")
    new_pin = inputs[1].strip()
    if not valid_pin(new_pin):
        return end("PIN must be 4-8 digits.")

    if len(inputs) == 2:
        return con("Long-term recovery code (from your offline notes)?")
    long_code = inputs[2].strip().upper()

    try:
        dek = crypto.unwrap_dek_with_recovery(
            long_code,
            user.rec_salt,
            user.dek_wrapped_rec,
            user.dek_wrapped_rec_nonce,
            pepper,
        )
    except crypto.CryptoError:
        await audit_log(db, msisdn=msisdn, event="recovery_wrong_longcode", success=False)
        return end("Wrong long-term recovery code. Vault unchanged.")

    # Re-wrap under new PIN. Rotate the long-term recovery wrap too.
    pin_verifier, pin_salt, pin_wrap, pin_nonce = crypto.rewrap_with_new_pin(dek, new_pin, pepper)
    rec_verifier, rec_salt, rec_wrap, rec_nonce, new_long_code = crypto.rotate_recovery(dek, pepper)
    user.pin_verifier = pin_verifier
    user.pin_salt = pin_salt
    user.dek_wrapped_pin = pin_wrap
    user.dek_wrapped_pin_nonce = pin_nonce
    user.recovery_verifier = rec_verifier
    user.rec_salt = rec_salt
    user.dek_wrapped_rec = rec_wrap
    user.dek_wrapped_rec_nonce = rec_nonce
    user.failed_attempts = 0
    user.locked_until = None
    # Consume the SMS token
    await db.execute(delete(RecoveryToken).where(RecoveryToken.msisdn == msisdn))
    await db.commit()
    send_recovery_code(msisdn, new_long_code)
    await audit_log(db, msisdn=msisdn, event="recovery_success", success=True)
    return end("PIN reset. A new long-term recovery code was SMSed — save it offline.")
