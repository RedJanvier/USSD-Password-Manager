"""Change-PIN flow.

  6*<old_pin>
  6*<old_pin>*<new_pin>
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.audit import log as audit_log
from app.config import get_settings
from app.rate_limit import is_locked, register_failure, register_success, seconds_until_unlock
from app.ussd.flows._common import find_user, valid_pin
from app.ussd.responses import con, end


async def handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    pepper = get_settings().pepper_bytes
    user = await find_user(db, msisdn)
    if user is None:
        return end("No vault on this number.")
    if is_locked(user):
        return end(f"Vault locked. Try again in {seconds_until_unlock(user)}s.")

    if len(inputs) == 0:
        return con("Current PIN?")
    old_pin = inputs[0].strip()
    if not valid_pin(old_pin):
        return end("PIN must be 4-8 digits.")

    try:
        crypto.verify_pin(old_pin, user.pin_verifier, pepper)
    except crypto.CryptoError:
        await register_failure(db, user)
        await audit_log(db, msisdn=msisdn, event="wrong_pin", success=False)
        if is_locked(user):
            return end(f"Wrong PIN. Vault locked for {seconds_until_unlock(user)}s.")
        return end("Wrong PIN.")
    await register_success(db, user)

    if len(inputs) == 1:
        return con("New 4-8 digit PIN?")
    new_pin = inputs[1].strip()
    if not valid_pin(new_pin):
        return end("PIN must be 4-8 digits.")
    if new_pin == old_pin:
        return end("New PIN must differ from current.")

    dek = crypto.unwrap_dek_with_pin(
        old_pin, user.pin_salt, user.dek_wrapped_pin, user.dek_wrapped_pin_nonce, pepper
    )
    verifier, new_salt, new_wrapped, new_nonce = crypto.rewrap_with_new_pin(dek, new_pin, pepper)
    user.pin_verifier = verifier
    user.pin_salt = new_salt
    user.dek_wrapped_pin = new_wrapped
    user.dek_wrapped_pin_nonce = new_nonce
    await db.commit()
    await audit_log(db, msisdn=msisdn, event="change_pin", success=True)
    return end("PIN changed.")
