"""Drive the USSD endpoint from your terminal.

Run the server in one window:
    uv run uvicorn app.main:app --reload

Then this script in another:
    uv run python scripts/simulate_ussd.py

It mimics what Africa's Talking sends: an HTTP POST with sessionId, serviceCode,
phoneNumber, and text (the cumulative *-joined input). Each time you type a
response, it's appended to text with a `*` separator, exactly like AT does.
Press Ctrl-C to end the session.
"""

from __future__ import annotations

import argparse
import sys
import uuid

import httpx


def run(base_url: str, msisdn: str, service_code: str) -> None:
    session_id = uuid.uuid4().hex
    text = ""
    print(f"\nDialing {service_code} from {msisdn} (session {session_id[:8]})\n")

    while True:
        with httpx.Client() as client:
            resp = client.post(
                f"{base_url}/ussd",
                data={
                    "sessionId": session_id,
                    "serviceCode": service_code,
                    "phoneNumber": msisdn,
                    "text": text,
                },
                timeout=30,
            )
        body = resp.text
        if body.startswith("CON "):
            print("─" * 50)
            print(body[4:])
            print("─" * 50)
            try:
                user_input = input("> ")
            except (EOFError, KeyboardInterrupt):
                print("\n[session ended by user]")
                return
            text = f"{text}*{user_input}" if text else user_input
        elif body.startswith("END "):
            print("═" * 50)
            print(body[4:])
            print("═" * 50)
            return
        else:
            print("[unexpected server response]:", body)
            return


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--msisdn", default="+250788000001")
    p.add_argument("--shortcode", default="*384*0#")
    args = p.parse_args()
    try:
        run(args.url, args.msisdn, args.shortcode)
    except httpx.ConnectError:
        print(
            f"Could not reach {args.url}. Start the server with:\n"
            f"  uv run uvicorn app.main:app --reload"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
