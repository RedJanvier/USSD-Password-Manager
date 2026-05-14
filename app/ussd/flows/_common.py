"""Shared helpers used across flows.

Each flow takes `inputs: list[str]` — the cumulative `text` after the leading
menu digit, split on `*`. So when the user dials `*384*0#`, picks 1, types
"icloud", the `text` field is `1*icloud`, and the save flow sees inputs == [
"icloud"].
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User

PIN_RE = re.compile(r"^\d{4,8}$")
SITE_RE = re.compile(r"^[A-Za-z0-9 ._\-]{1,40}$")


def valid_pin(s: str) -> bool:
    return bool(PIN_RE.fullmatch(s))


def valid_site(s: str) -> bool:
    return bool(SITE_RE.fullmatch(s))


async def find_user(db: AsyncSession, msisdn: str) -> User | None:
    return (await db.execute(select(User).where(User.msisdn == msisdn))).scalar_one_or_none()
