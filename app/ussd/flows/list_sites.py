"""List flow — read-only. Lists site names this MSISDN has saved.

Site names aren't sensitive in our threat model (the carrier already sees them
anyway, since saves and gets pass through USSD). So we don't require a PIN
just to list them. If that calculus changes, gate this behind PIN verify."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import VaultEntry
from app.ussd.responses import MAX_USSD_BODY, end


async def handle(msisdn: str, inputs: list[str], db: AsyncSession) -> str:
    rows = (
        await db.execute(
            select(VaultEntry.site_name)
            .where(VaultEntry.msisdn == msisdn)
            .order_by(VaultEntry.site_name)
        )
    ).scalars().all()

    if not rows:
        return end("No saved sites. Menu option 1 to save one.")

    body = "Saved sites:\n" + "\n".join(f"- {r}" for r in rows)
    # If the list overflows, show what fits + a count
    if len(body) <= MAX_USSD_BODY:
        return end(body)
    shown: list[str] = []
    length = len("Saved sites:\n")
    for r in rows:
        line = f"- {r}\n"
        if length + len(line) + 20 > MAX_USSD_BODY:
            break
        shown.append(line)
        length += len(line)
    remaining = len(rows) - len(shown)
    return end("Saved sites:\n" + "".join(shown) + f"…+{remaining} more")
