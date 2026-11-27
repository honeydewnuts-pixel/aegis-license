# aegis-licence

Standalone **AEGIS licence verification service** for `licence.leveragefx.co`.

## This repository is

- The licence HTTP service (`POST /aegis/licence`, `GET /healthz`)
- A **read-only** mobile dashboard (`/dashboard/`)
- Deploy config for a **separate** Render service

## This repository is NOT

- The AEGIS trading platform (`AEGIS_Platform_Server`)
- The MT5 EA / any `.mq5` code
- A place to store `AEGIS_VENDOR_KEY_HEX` or other secrets

## Layout

```
licence_service/   # verbatim licence core (do not casually rewrite)
dashboard/         # PWA UI (new)
dashboard_api.py   # read-only API (new)
wsgi.py            # mounts licence + dashboard
tests/             # licence unit tests
render.yaml        # Render blueprint (no secret values)
```

## Local tests

```bash
export AEGIS_VENDOR_KEY_HEX=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export AEGIS_LICENCE_DB_PATH=/tmp/test_licences.db
python -m unittest -v tests.test_licence_service
```

Expect **26 tests, OK**.

## Start (local)

```bash
export AEGIS_VENDOR_KEY_HEX=...   # 64+ hex, not a known/weak key
export AEGIS_DASHBOARD_TOKEN=...  # dashboard login only
export AEGIS_LICENCE_DB_PATH=/tmp/licences.db
export AEGIS_REQUIRE_HTTPS=false
pip install -r requirements.txt
gunicorn wsgi:application --bind 127.0.0.1:8080 --workers 1 --threads 4
```

- Health: `http://127.0.0.1:8080/healthz`
- Dashboard: `http://127.0.0.1:8080/dashboard/`

## Production URLs (after owner DNS)

- `https://licence.leveragefx.co/healthz`
- `https://licence.leveragefx.co/aegis/licence`
- `https://licence.leveragefx.co/dashboard/`
