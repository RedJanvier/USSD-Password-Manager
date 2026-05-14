"""Server-side session storage.

USSD itself is "stateless" in that Africa's Talking re-sends the full cumulative
`text` on every step — so most of the time we just re-derive state from that.
The one case where we need the DB is **long-password continuation**: if a
retrieved password doesn't fit in 178 chars, we end the session with "1/2 —
dial again with same code to see rest" and stash the remainder here, keyed by
msisdn, with a short TTL.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import UssdSession
from app.timeutil import aware, now

DEFAULT_TTL_SECONDS = 120


async def put(
    db: AsyncSession,
    session_id: str,
    msisdn: str,
    state: dict[str, Any],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> None:
    await db.execute(delete(UssdSession).where(UssdSession.session_id == session_id))
    db.add(
        UssdSession(
            session_id=session_id,
            msisdn=msisdn,
            state=state,
            expires_at=now() + timedelta(seconds=ttl_seconds),
        )
    )
    await db.commit()


async def get(db: AsyncSession, session_id: str) -> dict[str, Any] | None:
    row = (await db.execute(select(UssdSession).where(UssdSession.session_id == session_id))).scalar_one_or_none()
    if row is None:
        return None
    if aware(row.expires_at) < now():
        await db.execute(delete(UssdSession).where(UssdSession.session_id == session_id))
        await db.commit()
        return None
    return row.state


async def pop(db: AsyncSession, session_id: str) -> dict[str, Any] | None:
    state = await get(db, session_id)
    if state is not None:
        await db.execute(delete(UssdSession).where(UssdSession.session_id == session_id))
        await db.commit()
    return state


async def find_for_msisdn(db: AsyncSession, msisdn: str, kind: str) -> dict[str, Any] | None:
    """Find a non-expired session row for a given msisdn whose state.kind == kind.
    Used for the long-password continuation flow — the user dials again from
    the same number to fetch the next chunk."""
    rows = (
        await db.execute(select(UssdSession).where(UssdSession.msisdn == msisdn))
    ).scalars().all()
    cutoff = now()
    for r in rows:
        if aware(r.expires_at) >= cutoff and r.state.get("kind") == kind:
            return r.state
    return None
