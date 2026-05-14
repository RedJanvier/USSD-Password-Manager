"""POST /ussd — Africa's Talking USSD webhook.

Africa's Talking sends:
  sessionId   — stable per session
  serviceCode — the shortcode dialed (e.g. *384*12345#)
  phoneNumber — MSISDN in E.164 (e.g. +250788123456)
  text        — cumulative user input, *-separated

We always reply text/plain starting with "CON " (continue) or "END " (stop).

This module is the *only* USSD entry point. It parses, dispatches to a flow,
and never decodes more than `text.split("*")` because that's the literal
contract with the aggregator.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, Form
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.ussd.flows import change_pin as f_change_pin
from app.ussd.flows import get as f_get
from app.ussd.flows import list_sites as f_list
from app.ussd.flows import recovery as f_recovery
from app.ussd.flows import save as f_save
from app.ussd.responses import HELP, WELCOME, con, end

log = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/ussd", response_class=PlainTextResponse)
async def ussd(
    sessionId: str = Form(default=""),
    serviceCode: str = Form(default=""),
    phoneNumber: str = Form(default=""),
    text: str = Form(default=""),
    db: AsyncSession = Depends(get_session),
) -> str:
    msisdn = phoneNumber.strip()
    parts = text.split("*") if text else []

    log.info(
        "ussd.request",
        session_id=sessionId,
        service_code=serviceCode,
        msisdn_tail=msisdn[-4:] if msisdn else "",
        depth=len(parts),
    )

    if not parts or parts == [""]:
        return con(WELCOME)

    choice, rest = parts[0], parts[1:]
    try:
        match choice:
            case "1":
                return await f_save.handle(msisdn, rest, db)
            case "2":
                return await f_get.handle(msisdn, rest, db)
            case "3":
                return await f_list.handle(msisdn, rest, db)
            case "4":
                return await f_recovery.request_handle(msisdn, rest, db)
            case "5":
                return await f_recovery.redeem_handle(msisdn, rest, db)
            case "6":
                return await f_change_pin.handle(msisdn, rest, db)
            case "0":
                return end(HELP)
            case _:
                return end("Invalid option. Dial again.")
    except Exception:  # noqa: BLE001
        log.exception("ussd.unhandled", session_id=sessionId)
        return end("Something went wrong. Try again.")
