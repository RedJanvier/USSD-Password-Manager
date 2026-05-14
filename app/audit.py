from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def log(
    db: AsyncSession,
    *,
    msisdn: str | None,
    event: str,
    success: bool,
    site_name: str | None = None,
) -> None:
    db.add(AuditLog(msisdn=msisdn, event=event, success=success, site_name=site_name))
    await db.commit()
