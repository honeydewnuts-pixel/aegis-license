# Dashboard (read-only PWA)

Mobile-first licence viewer. Not the EA. Not the trading platform.

- Auth: `AEGIS_DASHBOARD_TOKEN` in host env only
- Login: `POST /api/dashboard/login`
- Issue/revoke: admin CLI only

Local:

```bash
export AEGIS_VENDOR_KEY_HEX=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export AEGIS_DASHBOARD_TOKEN=local-dev-token
export AEGIS_LICENCE_DB_PATH=/tmp/licences.db
export AEGIS_REQUIRE_HTTPS=false
pip install -r ../requirements.txt
gunicorn wsgi:application --bind 127.0.0.1:8080 --workers 1 --threads 4
# open http://127.0.0.1:8080/dashboard/
```
