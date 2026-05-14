"""Envelope encryption for the vault.

Threat model and design rationale live in `app/crypto.py` and the project plan.
The short version:

* Each user has a 256-bit DEK (data encryption key) that is never stored in plain.
* The DEK is wrapped twice: once under a KEK derived from the user's PIN, and once
  under a KEK derived from an SMS-delivered recovery code. Either KEK can unwrap
  the DEK; the recovery wrap is rotated every time it's used.
* All KDFs include a server-side pepper, so a DB-only leak isn't enough to brute
  force PINs.
* Each vault entry is encrypted with AES-256-GCM, with AAD = msisdn || lower(site)
  so ciphertexts can't be swapped between rows or users.

Nothing here touches the database — these are pure functions over bytes. The DB
layer is responsible for persisting the byte blobs this module produces.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type as LowType
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id parameters. 64 MiB / 3 iterations is the OWASP 2024 recommendation
# for password hashing — generous enough that even on a fast server, brute
# forcing a 4-digit PIN against a leaked DB costs millions of dollars in compute.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32  # 256-bit KEK

DEK_LEN = 32  # AES-256
NONCE_LEN = 12  # AES-GCM standard
SALT_LEN = 16
RECOVERY_CODE_LEN = 10  # ~52 bits of entropy from base32 alphabet
RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L

# Separator used inside the encrypted plaintext to delimit username and password.
# 0x1F is ASCII "unit separator" — never appears in typed input.
PLAINTEXT_SEP = b"\x1f"

# Hasher used only for the PIN verifier (fast-path wrong-PIN rejection before
# we attempt the expensive KEK derive + GCM unwrap).
_PIN_VERIFIER_HASHER = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    type=Type.ID,
)


class CryptoError(Exception):
    """Raised on any verification, unwrap, or decrypt failure.

    We deliberately collapse all failures into one exception type so the
    USSD layer can't accidentally leak *why* something failed (wrong PIN
    vs. corrupted ciphertext vs. tampered AAD) through different error
    messages.
    """


@dataclass(frozen=True)
class UserSecrets:
    """Everything the DB needs to store for a new user.

    `recovery_code_plain` is returned exactly once at registration (or after
    a recovery) and must be SMSed to the user immediately, then discarded.
    The server only keeps the Argon2 hash of it (via `recovery_verifier`).
    """

    pin_verifier: str
    pin_salt: bytes
    rec_salt: bytes
    dek_wrapped_pin: bytes
    dek_wrapped_pin_nonce: bytes
    dek_wrapped_rec: bytes
    dek_wrapped_rec_nonce: bytes
    recovery_verifier: str
    recovery_code_plain: str  # to be SMSed, never stored


def _derive_kek(secret: str, salt: bytes, pepper: bytes) -> bytes:
    """KDF for both PIN-KEK and recovery-KEK. Pepper is mixed into the password."""
    return hash_secret_raw(
        secret=secret.encode("utf-8") + b":" + pepper,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=LowType.ID,
    )


def _wrap(kek: bytes, dek: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(kek).encrypt(nonce, dek, associated_data=b"dek-wrap")
    return ct, nonce


def _unwrap(kek: bytes, ct: bytes, nonce: bytes) -> bytes:
    try:
        return AESGCM(kek).decrypt(nonce, ct, associated_data=b"dek-wrap")
    except Exception as exc:
        raise CryptoError("unwrap failed") from exc


def _gen_recovery_code() -> str:
    return "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(RECOVERY_CODE_LEN))


def create_user(pin: str, pepper: bytes) -> UserSecrets:
    """Register a fresh user. Returns secrets to persist + the plaintext
    recovery code, which must be SMSed and then discarded."""
    dek = secrets.token_bytes(DEK_LEN)
    pin_salt = secrets.token_bytes(SALT_LEN)
    rec_salt = secrets.token_bytes(SALT_LEN)

    kek_pin = _derive_kek(pin, pin_salt, pepper)
    dek_wrapped_pin, pin_nonce = _wrap(kek_pin, dek)

    recovery_code = _gen_recovery_code()
    kek_rec = _derive_kek(recovery_code, rec_salt, pepper)
    dek_wrapped_rec, rec_nonce = _wrap(kek_rec, dek)

    pin_verifier = _PIN_VERIFIER_HASHER.hash(pin + ":" + pepper.hex())
    rec_verifier = _PIN_VERIFIER_HASHER.hash(recovery_code + ":" + pepper.hex())

    return UserSecrets(
        pin_verifier=pin_verifier,
        pin_salt=pin_salt,
        rec_salt=rec_salt,
        dek_wrapped_pin=dek_wrapped_pin,
        dek_wrapped_pin_nonce=pin_nonce,
        dek_wrapped_rec=dek_wrapped_rec,
        dek_wrapped_rec_nonce=rec_nonce,
        recovery_verifier=rec_verifier,
        recovery_code_plain=recovery_code,
    )


def verify_pin(pin: str, verifier: str, pepper: bytes) -> None:
    try:
        _PIN_VERIFIER_HASHER.verify(verifier, pin + ":" + pepper.hex())
    except VerifyMismatchError as exc:
        raise CryptoError("wrong pin") from exc


def verify_recovery(code: str, verifier: str, pepper: bytes) -> None:
    try:
        _PIN_VERIFIER_HASHER.verify(verifier, code + ":" + pepper.hex())
    except VerifyMismatchError as exc:
        raise CryptoError("wrong recovery code") from exc


def unwrap_dek_with_pin(
    pin: str,
    pin_salt: bytes,
    dek_wrapped_pin: bytes,
    dek_wrapped_pin_nonce: bytes,
    pepper: bytes,
) -> bytes:
    kek = _derive_kek(pin, pin_salt, pepper)
    return _unwrap(kek, dek_wrapped_pin, dek_wrapped_pin_nonce)


def unwrap_dek_with_recovery(
    code: str,
    rec_salt: bytes,
    dek_wrapped_rec: bytes,
    dek_wrapped_rec_nonce: bytes,
    pepper: bytes,
) -> bytes:
    kek = _derive_kek(code, rec_salt, pepper)
    return _unwrap(kek, dek_wrapped_rec, dek_wrapped_rec_nonce)


@dataclass(frozen=True)
class RewrapResult:
    pin_verifier: str
    pin_salt: bytes
    rec_salt: bytes
    dek_wrapped_pin: bytes
    dek_wrapped_pin_nonce: bytes
    dek_wrapped_rec: bytes
    dek_wrapped_rec_nonce: bytes
    recovery_verifier: str
    recovery_code_plain: str  # new code to SMS the user


def rewrap_with_new_pin(dek: bytes, new_pin: str, pepper: bytes) -> tuple[str, bytes, bytes, bytes]:
    """Wrap an existing DEK under a fresh PIN. Returns
    (pin_verifier, pin_salt, dek_wrapped_pin, dek_wrapped_pin_nonce).
    The recovery wrap is left untouched by this operation."""
    pin_salt = secrets.token_bytes(SALT_LEN)
    kek = _derive_kek(new_pin, pin_salt, pepper)
    wrapped, nonce = _wrap(kek, dek)
    verifier = _PIN_VERIFIER_HASHER.hash(new_pin + ":" + pepper.hex())
    return verifier, pin_salt, wrapped, nonce


def rotate_recovery(dek: bytes, pepper: bytes) -> tuple[str, bytes, bytes, bytes, str]:
    """Generate a brand-new recovery code, wrap the DEK under it, and return
    (recovery_verifier, rec_salt, dek_wrapped_rec, dek_wrapped_rec_nonce, recovery_code_plain).
    Call this on first registration *and* after every successful recovery use."""
    code = _gen_recovery_code()
    rec_salt = secrets.token_bytes(SALT_LEN)
    kek = _derive_kek(code, rec_salt, pepper)
    wrapped, nonce = _wrap(kek, dek)
    verifier = _PIN_VERIFIER_HASHER.hash(code + ":" + pepper.hex())
    return verifier, rec_salt, wrapped, nonce, code


# ─── Vault entry encryption ─────────────────────────────────────────────────

def _aad_for(msisdn: str, site_name: str) -> bytes:
    return f"{msisdn}|{site_name.lower()}".encode("utf-8")


def encrypt_entry(
    dek: bytes, msisdn: str, site_name: str, username: str, password: str
) -> tuple[bytes, bytes]:
    """Returns (ciphertext, nonce)."""
    nonce = secrets.token_bytes(NONCE_LEN)
    plaintext = username.encode("utf-8") + PLAINTEXT_SEP + password.encode("utf-8")
    ct = AESGCM(dek).encrypt(nonce, plaintext, associated_data=_aad_for(msisdn, site_name))
    return ct, nonce


def decrypt_entry(
    dek: bytes, msisdn: str, site_name: str, ciphertext: bytes, nonce: bytes
) -> tuple[str, str]:
    """Returns (username, password). Raises CryptoError on any tampering."""
    try:
        plaintext = AESGCM(dek).decrypt(
            nonce, ciphertext, associated_data=_aad_for(msisdn, site_name)
        )
    except Exception as exc:
        raise CryptoError("entry decrypt failed") from exc
    parts = plaintext.split(PLAINTEXT_SEP, 1)
    if len(parts) != 2:
        raise CryptoError("malformed plaintext")
    return parts[0].decode("utf-8"), parts[1].decode("utf-8")
