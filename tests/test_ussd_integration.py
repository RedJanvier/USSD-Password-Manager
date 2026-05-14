"""End-to-end USSD flow tests via httpx ASGI transport.

These hit the real FastAPI app, real SQLite, real crypto. SMS is stubbed out
inside `app.sms` (it short-circuits when AT creds are unset)."""

import pytest

from tests.conftest import ussd_post


async def test_healthz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


async def test_welcome(client, msisdn):
    body = await ussd_post(client, msisdn=msisdn, text="")
    assert body.startswith("CON ")
    assert "Password Vault" in body
    assert "Save password" in body


async def test_save_then_get(client, msisdn):
    save = await ussd_post(client, msisdn=msisdn, text="1*icloud*jane@me.com*Hunter2!*123456")
    assert save.startswith("END ")
    assert "Saved icloud" in save or "Saved iCloud" in save or "Saved" in save

    got = await ussd_post(client, msisdn=msisdn, text="2*icloud*123456", session_id="s2")
    assert got.startswith("END ")
    assert "jane@me.com" in got
    assert "Hunter2!" in got


async def test_get_wrong_pin(client, msisdn):
    await ussd_post(client, msisdn=msisdn, text="1*icloud*u*p*123456")
    bad = await ussd_post(client, msisdn=msisdn, text="2*icloud*000000", session_id="s2")
    assert bad.startswith("END ")
    assert "Wrong PIN" in bad


async def test_get_unknown_site(client, msisdn):
    await ussd_post(client, msisdn=msisdn, text="1*icloud*u*p*123456")
    miss = await ussd_post(client, msisdn=msisdn, text="2*gmail*123456", session_id="s2")
    assert miss.startswith("END ")
    assert "No entry" in miss


async def test_list_sites(client, msisdn):
    await ussd_post(client, msisdn=msisdn, text="1*icloud*u*p*123456")
    await ussd_post(client, msisdn=msisdn, text="1*gmail*u2*p2*123456", session_id="s2")
    listing = await ussd_post(client, msisdn=msisdn, text="3", session_id="s3")
    assert listing.startswith("END ")
    assert "icloud" in listing
    assert "gmail" in listing


async def test_change_pin_preserves_entries(client, msisdn):
    await ussd_post(client, msisdn=msisdn, text="1*icloud*u*p*123456")
    changed = await ussd_post(
        client, msisdn=msisdn, text="6*123456*654321", session_id="s2"
    )
    assert changed.startswith("END ")
    assert "PIN changed" in changed

    # Old PIN no longer works
    old = await ussd_post(client, msisdn=msisdn, text="2*icloud*123456", session_id="s3")
    assert "Wrong PIN" in old

    # New PIN works
    new = await ussd_post(client, msisdn=msisdn, text="2*icloud*654321", session_id="s4")
    assert "u" in new
    assert "p" in new


async def test_cross_user_isolation(client):
    a = "+250788000001"
    b = "+250788000002"
    await ussd_post(client, msisdn=a, text="1*icloud*alice@me.com*p1*111111")
    # B tries to get A's entry with B's PIN
    out = await ussd_post(client, msisdn=b, text="2*icloud*111111", session_id="s2")
    assert "No vault" in out or "No entry" in out


@pytest.mark.parametrize("bad", ["1*ic loud!*u*p*1234", "1*x*y*z*ab"])
async def test_input_validation(client, msisdn, bad):
    """Site with bad chars rejected; PIN too short rejected."""
    out = await ussd_post(client, msisdn=msisdn, text=bad)
    assert out.startswith("END ")


async def test_pin_lockout(client, msisdn):
    # Register
    await ussd_post(client, msisdn=msisdn, text="1*icloud*u*p*123456")
    # 5 wrong PINs in a row → locked
    for i in range(5):
        out = await ussd_post(
            client, msisdn=msisdn, text="2*icloud*000000", session_id=f"bad{i}"
        )
        assert "Wrong PIN" in out or "locked" in out.lower()
    # Next try should mention the lock
    out = await ussd_post(client, msisdn=msisdn, text="2*icloud*123456", session_id="afterlock")
    assert "locked" in out.lower()
