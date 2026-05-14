"""Save flow.

Steps (each is one user keystroke-screen):
  1*<site>
  1*<site>*<username>
  1*<site>*<username>*<password>
  1*<site>*<username>*<password>*<pin>

If the user has never registered before, the PIN they type here becomes their
master PIN and we generate a fresh recovery code (SMSed at the end).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.audit import log as audit_log
from app.config import get_settings
from app.models import User, VaultEntry
from app.rate_limit import is_locked, register_failure, register_success, seconds_until_unlock
from app.sms import send_recovery_code
from app.ussd.flows._common import find_user, valid_pin, valid_site
from app.ussd.responses import con, end


async def handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    pepper = get_settings().pepper_bytes

    if len(inputs) == 0:
        return con("Site or app name?")

    site = inputs[0].strip()
    if not valid_site(site):
        return end("Site name must be letters/digits/space/._- and up to 40 chars.")

    if len(inputs) == 1:
        return con(f"Site: {site}\nUsername/email?")
    username = inputs[1].strip()
    if not username:
        return end("Username can't be empty.")

    if len(inputs) == 2:
        return con("Password to store?")
    password = inputs[2]
    if not password:
        return end("Password can't be empty.")

    if len(inputs) == 3:
        return con("4-8 digit PIN to protect your vault?")
    pin = inputs[3].strip()
    if not valid_pin(pin):
        return end("PIN must be 4-8 digits.")

    user = await find_user(db, msisdn)

    if user is None:
        # First save — register user, generate recovery code, persist entry.
        secrets = crypto.create_user(pin, pepper)
        user = User(
            msisdn=msisdn,
            pin_verifier=secrets.pin_verifier,
            pin_salt=secrets.pin_salt,
            rec_salt=secrets.rec_salt,
            dek_wrapped_pin=secrets.dek_wrapped_pin,
            dek_wrapped_pin_nonce=secrets.dek_wrapped_pin_nonce,
            dek_wrapped_rec=secrets.dek_wrapped_rec,
            dek_wrapped_rec_nonce=secrets.dek_wrapped_rec_nonce,
            recovery_verifier=secrets.recovery_verifier,
        )
        db.add(user)
        dek = crypto.unwrap_dek_with_pin(
            pin,
            secrets.pin_salt,
            secrets.dek_wrapped_pin,
            secrets.dek_wrapped_pin_nonce,
            pepper,
        )
        await _persist_entry(db, msisdn, site, username, password, dek)
        send_recovery_code(msisdn, secrets.recovery_code_plain)
        await audit_log(db, msisdn=msisdn, event="register+save", success=True, site_name=site.lower())
        return end(
            f"Saved {site}. You've been registered — a recovery code was SMSed to you. "
            "Save it offline; you'll need it if you forget your PIN."
        )

    # Returning user — verify PIN, unwrap DEK, save entry.
    if is_locked(user):
        return end(f"Vault locked. Try again in {seconds_until_unlock(user)}s.")
    try:
        crypto.verify_pin(pin, user.pin_verifier, pepper)
    except crypto.CryptoError:
        await register_failure(db, user)
        await audit_log(db, msisdn=msisdn, event="wrong_pin", success=False, site_name=site.lower())
        if is_locked(user):
            return end(f"Wrong PIN. Vault locked for {seconds_until_unlock(user)}s.")
        return end("Wrong PIN.")
    await register_success(db, user)

    dek = crypto.unwrap_dek_with_pin(
        pin, user.pin_salt, user.dek_wrapped_pin, user.dek_wrapped_pin_nonce, pepper
    )
    await _persist_entry(db, msisdn, site, username, password, dek)
    await audit_log(db, msisdn=msisdn, event="save", success=True, site_name=site.lower())
    return end(f"Saved {site}.")


async def _persist_entry(
    db: AsyncSession, msisdn: str, site: str, username: str, password: str, dek: bytes
) -> None:
    site_lc = site.lower()
    ct, nonce = crypto.encrypt_entry(dek, msisdn, site_lc, username, password)
    existing = (
        await db.execute(
            select(VaultEntry).where(VaultEntry.msisdn == msisdn, VaultEntry.site_name == site_lc)
        )
    ).scalar_one_or_none()
    if existing:
        existing.ciphertext = ct
        existing.nonce = nonce
    else:
        db.add(VaultEntry(msisdn=msisdn, site_name=site_lc, ciphertext=ct, nonce=nonce))
    await db.commit()
