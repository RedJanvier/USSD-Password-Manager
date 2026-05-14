"""Helpers for the two USSD response prefixes Africa's Talking expects.

`CON ` keeps the session open and shows the body as the next prompt.
`END ` closes the session and shows the body as the final message.

USSD has a hard 182-character limit per response across the whole network.
We truncate defensively: anything past 178 chars gets cut and replaced with
`…[cut]` so the user knows the message was longer than the channel allows.
"""

MAX_USSD_BODY = 178


def _clamp(body: str) -> str:
    if len(body) <= MAX_USSD_BODY:
        return body
    return body[: MAX_USSD_BODY - 7] + "…[cut]"


def con(body: str) -> str:
    return "CON " + _clamp(body)


def end(body: str) -> str:
    return "END " + _clamp(body)


WELCOME = (
    "Password Vault\n"
    "1. Save password\n"
    "2. Get password\n"
    "3. List sites\n"
    "4. Forgot PIN\n"
    "5. Enter recovery code\n"
    "6. Change PIN\n"
    "0. Help"
)

HELP = (
    "Saves passwords by site. Bound to your number. PIN protects access. "
    "Do NOT store iCloud, banking, or work SSO here — USSD is not end-to-end "
    "encrypted. Best for wifi, app PINs, recovery hints."
)
