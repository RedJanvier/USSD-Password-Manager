# USSD Password Manager

Dial a short code from any phone — even a feature phone — and recall passwords you saved earlier. Built for Rwanda / East Africa via Africa's Talking.

## ⚠️ Read this before using

USSD is **plaintext over the GSM signalling channel**. The mobile carrier (and anyone with carrier-level access) can see every keystroke and every response. The server-side crypto in this project (Argon2id + AES-256-GCM envelope encryption) makes a *server compromise* survivable, but it **cannot** hide traffic from a hostile telco.

**Use it for:** wifi passwords, app PINs, loyalty cards, account hints, gate codes, recovery phrases.
**Do NOT use it for:** iCloud, banking, work SSO, anything with money or identity at stake.

## What's in the box

- FastAPI webhook that responds to Africa's Talking USSD callbacks.
- Two-wrap envelope encryption: every user's vault key (DEK) is wrapped once under their PIN and once under an SMS-delivered recovery code.
- PIN attempts are rate-limited and the account locks before brute force becomes viable.
- Postgres in production, SQLite for local dev — same code, different `DATABASE_URL`.
- Local CLI simulator so you can walk every menu without a phone.

## Quick start (local)

You need Python 3.11+ — install [uv](https://docs.astral.sh/uv/) for the easiest setup:

```powershell
# Windows PowerShell — installs uv (a single binary, no admin needed)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Then from the repo root:
uv sync                          # creates .venv and installs everything
Copy-Item .env.example .env
# Edit .env — at minimum set APP_PEPPER to 64 random hex chars:
#   python -c "import secrets; print(secrets.token_hex(32))"

uv run alembic upgrade head      # creates vault.db with all tables
uv run uvicorn app.main:app --reload
```

In a second terminal, drive the menus from your keyboard:

```powershell
uv run python scripts/simulate_ussd.py
```

Run the test suite:

```powershell
uv run pytest -v
```

## Deploy to Render

1. Push this repo to GitHub (private recommended).
2. In Render: **New → Blueprint → connect repo**. Render reads `render.yaml`, provisions the web service + Postgres.
3. In the service's **Environment** tab, set:
   - `APP_PEPPER` — `python -c "import secrets; print(secrets.token_hex(32))"`
   - `AT_USERNAME` — `sandbox` initially
   - `AT_API_KEY` — from your Africa's Talking dashboard
   - `AT_SHORTCODE` — e.g. `*384*12345#` (the channel AT assigns you)
4. First deploy runs `alembic upgrade head` automatically. Copy the public URL — e.g. `https://ussd-pm.onrender.com`.

## Wire up Africa's Talking

**Sandbox (free, today):**

1. Sign up at [africastalking.com](https://africastalking.com), stay in **Sandbox** mode.
2. **USSD → Create Channel**, pick an unused channel, set callback to `https://<your-render-url>/ussd`.
3. Install the **Africa's Talking** Android app or open [simulator.africastalking.com](https://simulator.africastalking.com), log in, open the **USSD Simulator**, dial `*384*<channel>#`. You're now talking to your service.
4. SMS in sandbox only delivers to numbers you've added under **Sandbox Test Numbers** — add yours before testing recovery.

**Production:**

1. Switch the AT dashboard to **Live**, top up airtime, complete KYB.
2. **USSD → Request Shortcode** for MTN Rwanda / Airtel Rwanda / etc. Expect 1–4 weeks per operator, ~$50–150/mo lease.
3. Update `AT_USERNAME` / `AT_API_KEY` / `AT_SHORTCODE` env vars on Render to live values.
4. Anyone on the supported network can dial the shortcode — no install, no internet.

## How the menus work

```
*384*<channel>#

Password Vault
1. Save password
2. Get password
3. List sites
4. Forgot PIN
5. Change PIN
0. Help
```

First time you save a password, the system registers your MSISDN and asks for a PIN. A recovery code is generated and SMSed to you — **save it somewhere offline**. If you forget your PIN, dial in, choose **Forgot PIN**, get a fresh SMS code, and reset.

## Architecture & crypto details

See `app/crypto.py` for the envelope encryption. In short:

- `DEK` = random 256-bit per user, never persisted in clear.
- `KEK_pin = Argon2id(pin || pepper, salt_pin)` wraps the DEK.
- `KEK_recovery = Argon2id(recovery_code || pepper, salt_rec)` wraps a second copy of the DEK.
- Each vault entry: `AES-256-GCM(DEK, nonce, username || 0x1F || password, aad = msisdn || lower(site))`.
- A DB-only compromise yields ciphertexts + Argon2 hashes; without the PIN, recovery code, **and** the server-side pepper, decryption is intractable.

## Project layout

```
app/
  main.py              FastAPI app
  config.py            Pydantic settings
  db.py                SQLAlchemy async engine
  models.py            ORM tables
  crypto.py            Argon2id + AES-GCM envelope
  sms.py               Africa's Talking SMS wrapper
  rate_limit.py        PIN attempt lockout
  audit.py             Append-only event log
  ussd/
    router.py          POST /ussd handler
    menus.py           Pure-function state machine
    session_store.py   ussd_sessions table CRUD
    flows/             One module per top-level menu choice
migrations/            Alembic
scripts/
  simulate_ussd.py     Local CLI to walk menus without a phone
tests/                 pytest
```

## License

MIT — do whatever, but the security caveats above are on you.
