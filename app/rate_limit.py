"""PIN attempt counters and lockout. Pure logic over the User row + clock."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.timeutil import aware, now

# A short global lock that kicks in once `LOCKOUT_THRESHOLD` consecutive wrong
# PINs have been seen. The counter resets on a successful PIN entry.
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = timedelta(minutes=15)


def is_locked(user: User) -> bool:
    return user.locked_until is not None and aware(user.locked_until) > now()


def seconds_until_unlock(user: User) -> int:
    if user.locked_until is None:
        return 0
    delta = (aware(user.locked_until) - now()).total_seconds()
    return max(0, int(delta))


async def register_failure(db: AsyncSession, user: User) -> None:
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= LOCKOUT_THRESHOLD:
        user.locked_until = now() + LOCKOUT_DURATION
    await db.commit()


async def register_success(db: AsyncSession, user: User) -> None:
    if user.failed_attempts or user.locked_until:
        user.failed_attempts = 0
        user.locked_until = None
        await db.commit()
