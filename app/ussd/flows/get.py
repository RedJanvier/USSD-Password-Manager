"""Retrieve flow.

  2*<site>
  2*<site>*<pin>

If the rendered "user: …\npass: …" body exceeds the USSD char cap, the first
half is shown and the remainder is stashed in `ussd_sessions` keyed by msisdn.
The user dials the same code again, picks 2, types `cont`, gets the rest.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.audit import log as audit_log
from app.config import get_settings
from app.models import VaultEntry
from app.rate_limit import is_locked, register_failure, register_success, seconds_until_unlock
from app.ussd import session_store
from app.ussd.flows._common import find_user, valid_pin, valid_site
from app.ussd.responses import MAX_USSD_BODY, con, end

CONTINUATION_KIND = "get_continuation"


async def handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    pepper = get_settings().pepper_bytes

    # Continuation shortcut — user typed "cont" as first arg
    if len(inputs) >= 1 and inputs[0].strip().lower() == "cont":
        state = await session_store.find_for_msisdn(db, msisdn, CONTINUATION_KIND)
        if state is None:
            return end("Nothing to continue.")
        remaining = state.get("body", "")
        return await _render_with_continuation(db, msisdn, remaining)

    if len(inputs) == 0:
        return con("Site name? (Or type 'cont' to continue last retrieval)")

    site = inputs[0].strip()
    if not valid_site(site):
        return end("Site name must be letters/digits/space/._- and up to 40 chars.")

    if len(inputs) == 1:
        return con("PIN?")
    pin = inputs[1].strip()
    if not valid_pin(pin):
        return end("PIN must be 4-8 digits.")

    user = await find_user(db, msisdn)
    if user is None:
        return end("No vault on this number. Save a password first (menu option 1).")
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

    entry = (
        await db.execute(
            select(VaultEntry).where(
                VaultEntry.msisdn == msisdn, VaultEntry.site_name == site.lower()
            )
        )
    ).scalar_one_or_none()
    if entry is None:
        await audit_log(db, msisdn=msisdn, event="get_miss", success=False, site_name=site.lower())
        return end(f"No entry for '{site}'. Try menu option 3 to list sites.")

    dek = crypto.unwrap_dek_with_pin(
        pin, user.pin_salt, user.dek_wrapped_pin, user.dek_wrapped_pin_nonce, pepper
    )
    username, password = crypto.decrypt_entry(
        dek, msisdn, site.lower(), entry.ciphertext, entry.nonce
    )
    body = f"{site}\nuser: {username}\npass: {password}"
    await audit_log(db, msisdn=msisdn, event="get", success=True, site_name=site.lower())
    return await _render_with_continuation(db, msisdn, body)


async def _render_with_continuation(db: AsyncSession, msisdn: str, body: str) -> str:
    """If body fits, END with it. If not, END with first chunk and stash rest."""
    if len(body) <= MAX_USSD_BODY:
        return end(body)
    # Reserve 18 chars for the trailing "… dial again, type cont" hint.
    head_size = MAX_USSD_BODY - 22
    head = body[:head_size]
    tail = body[head_size:]
    await session_store.put(
        db, _continuation_id(msisdn), msisdn, {"kind": CONTINUATION_KIND, "body": tail}
    )
    return end(head + "\n…dial, 2, 'cont'")


def _continuation_id(msisdn: str) -> str:
    return f"continuation:{msisdn}"
