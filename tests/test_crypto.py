"""Crypto core tests. These run the real Argon2id parameters (64 MiB, t=3),
so the suite takes ~10s. That's deliberate: weakening params in tests would
let regressions in the production config slip through silently."""

import os

import pytest

from app import crypto

PEPPER = bytes.fromhex(
    "a1b2c3d4e5f6071829" "3a4b5c6d7e8f9a0b" "1c2d3e4f5a6b7c8d" "9e0f1a2b3c4d5e6f"
)
MSISDN = "+250788123456"


def test_create_user_round_trip_pin():
    secrets = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_pin(
        "123456",
        secrets.pin_salt,
        secrets.dek_wrapped_pin,
        secrets.dek_wrapped_pin_nonce,
        PEPPER,
    )
    assert len(dek) == crypto.DEK_LEN


def test_create_user_round_trip_recovery():
    s = crypto.create_user("123456", PEPPER)
    dek_via_pin = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    dek_via_rec = crypto.unwrap_dek_with_recovery(
        s.recovery_code_plain, s.rec_salt, s.dek_wrapped_rec, s.dek_wrapped_rec_nonce, PEPPER
    )
    assert dek_via_pin == dek_via_rec, "PIN and recovery must unwrap the same DEK"


def test_wrong_pin_raises():
    s = crypto.create_user("123456", PEPPER)
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek_with_pin(
            "000000", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
        )


def test_wrong_recovery_raises():
    s = crypto.create_user("123456", PEPPER)
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek_with_recovery(
            "WRONGCODEX", s.rec_salt, s.dek_wrapped_rec, s.dek_wrapped_rec_nonce, PEPPER
        )


def test_pin_verifier_matches():
    s = crypto.create_user("123456", PEPPER)
    crypto.verify_pin("123456", s.pin_verifier, PEPPER)  # no raise
    with pytest.raises(crypto.CryptoError):
        crypto.verify_pin("999999", s.pin_verifier, PEPPER)


def test_recovery_verifier_matches():
    s = crypto.create_user("123456", PEPPER)
    crypto.verify_recovery(s.recovery_code_plain, s.recovery_verifier, PEPPER)
    with pytest.raises(crypto.CryptoError):
        crypto.verify_recovery("WRONGCODEX", s.recovery_verifier, PEPPER)


def test_pepper_must_match():
    """A leaked DB without the pepper must be useless."""
    s = crypto.create_user("123456", PEPPER)
    different_pepper = os.urandom(32)
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek_with_pin(
            "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, different_pepper
        )


def test_entry_round_trip():
    s = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    ct, nonce = crypto.encrypt_entry(dek, MSISDN, "iCloud", "jane@me.com", "Hunter2!")
    user, pw = crypto.decrypt_entry(dek, MSISDN, "icloud", ct, nonce)
    assert user == "jane@me.com"
    assert pw == "Hunter2!"


def test_entry_aad_binding_site():
    """Ciphertext bound to site_name — swapping it must fail decryption."""
    s = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    ct, nonce = crypto.encrypt_entry(dek, MSISDN, "iCloud", "u", "p")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_entry(dek, MSISDN, "gmail", ct, nonce)


def test_entry_aad_binding_msisdn():
    """Cross-user ciphertext swap must fail decryption."""
    s = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    ct, nonce = crypto.encrypt_entry(dek, MSISDN, "iCloud", "u", "p")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_entry(dek, "+250788999999", "iCloud", ct, nonce)


def test_entry_ciphertext_tamper():
    s = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    ct, nonce = crypto.encrypt_entry(dek, MSISDN, "iCloud", "u", "p")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_entry(dek, MSISDN, "iCloud", bytes(tampered), nonce)


def test_pin_change_preserves_dek():
    """Changing PIN re-wraps the same DEK — existing entries stay decryptable."""
    s = crypto.create_user("123456", PEPPER)
    dek_before = crypto.unwrap_dek_with_pin(
        "123456", s.pin_salt, s.dek_wrapped_pin, s.dek_wrapped_pin_nonce, PEPPER
    )
    ct, nonce = crypto.encrypt_entry(dek_before, MSISDN, "iCloud", "u", "p")

    verifier, new_salt, new_wrapped, new_nonce = crypto.rewrap_with_new_pin(
        dek_before, "654321", PEPPER
    )
    dek_after = crypto.unwrap_dek_with_pin("654321", new_salt, new_wrapped, new_nonce, PEPPER)
    assert dek_before == dek_after

    user, pw = crypto.decrypt_entry(dek_after, MSISDN, "iCloud", ct, nonce)
    assert (user, pw) == ("u", "p")


def test_recovery_rotation():
    """Using recovery should generate a fresh code; old code stops working."""
    s = crypto.create_user("123456", PEPPER)
    dek = crypto.unwrap_dek_with_recovery(
        s.recovery_code_plain, s.rec_salt, s.dek_wrapped_rec, s.dek_wrapped_rec_nonce, PEPPER
    )

    new_verifier, new_salt, new_wrapped, new_nonce, new_code = crypto.rotate_recovery(dek, PEPPER)
    # New code unwraps
    dek2 = crypto.unwrap_dek_with_recovery(new_code, new_salt, new_wrapped, new_nonce, PEPPER)
    assert dek2 == dek
    # Old code does NOT unwrap the new blob
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek_with_recovery(s.recovery_code_plain, new_salt, new_wrapped, new_nonce, PEPPER)


def test_distinct_users_distinct_deks():
    a = crypto.create_user("123456", PEPPER)
    b = crypto.create_user("123456", PEPPER)  # same PIN, different user
    dek_a = crypto.unwrap_dek_with_pin(
        "123456", a.pin_salt, a.dek_wrapped_pin, a.dek_wrapped_pin_nonce, PEPPER
    )
    dek_b = crypto.unwrap_dek_with_pin(
        "123456", b.pin_salt, b.dek_wrapped_pin, b.dek_wrapped_pin_nonce, PEPPER
    )
    assert dek_a != dek_b, "same PIN must not produce same DEK across users"
