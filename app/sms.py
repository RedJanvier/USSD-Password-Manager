"""Africa's Talking SMS client. Single responsibility: send a recovery code.

Initializing `africastalking` is global state on the SDK side; we wrap it
behind a lazy initializer so unit tests can run without credentials and the
function can be monkeypatched in integration tests.
"""

from __future__ import annotations

import structlog

from app.config import get_settings

log = structlog.get_logger(__name__)

_initialized = False


def _ensure_initialized() -> None:
    global _initialized
    if _initialized:
        return
    import africastalking

    settings = get_settings()
    africastalking.initialize(settings.at_username, settings.at_api_key)
    _initialized = True


def send_recovery_code(msisdn: str, code: str) -> None:
    """Send the plain recovery code via SMS. Best-effort: failures are logged
    but do not raise — the USSD flow has already committed the new code to DB,
    and the user can request another one if SMS didn't arrive."""
    settings = get_settings()
    # In local/dev with no AT creds, just log and return so the simulator works.
    if not settings.at_api_key or settings.at_api_key in {"", "your-at-api-key"}:
        log.warning("sms.dry_run", msisdn=msisdn, code_preview=code[:2] + "***")
        return

    try:
        _ensure_initialized()
        import africastalking

        sms = africastalking.SMS
        message = (
            f"Password Vault recovery code: {code}\n"
            f"Valid 15 min. Don't share. Reply with menu option 5 after dialing."
        )
        resp = sms.send(message, [msisdn])
        log.info("sms.sent", msisdn=msisdn, resp=resp)
    except Exception as exc:  # noqa: BLE001 — never let SMS infra crash USSD
        log.error("sms.send_failed", msisdn=msisdn, error=str(exc))
