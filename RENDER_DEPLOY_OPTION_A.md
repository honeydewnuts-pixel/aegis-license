# Owner deploy checklist — Option A (separate service)

Builder cannot log into Render or your registrar. You do these five steps.

## 1. Create Web Service
- Render → New → Web Service
- Connect GitHub repo `honeydewnuts-pixel/aegis-licence`
- Name: **aegis-licence**
- Runtime: Python
- Build: `pip install -r requirements.txt`
- Start: `gunicorn wsgi:application --bind 0.0.0.0:$PORT --workers 1 --threads 4`
- Instances: 1

## 2. Disk
- Add disk, mount path **`/var/data`**, size **1 GB**

## 3. Environment (values only in Render UI)
| Key | Value |
|-----|--------|
| `AEGIS_REQUIRE_HTTPS` | `true` |
| `AEGIS_LICENCE_DB_PATH` | `/var/data/licences.db` |
| `AEGIS_RATE_LIMIT_PER_IP_PER_MIN` | `30` |
| `AEGIS_RATE_LIMIT_PER_SERIAL_PER_MIN` | `20` |
| `PYTHON_VERSION` | `3.11.9` |
| `AEGIS_VENDOR_KEY_HEX` | **you generate offline, never in git/chat** |
| `AEGIS_DASHBOARD_TOKEN` | **you choose, dashboard login only** |

Generate vendor key offline:
```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

## 4. Custom domain
Render → Settings → Custom Domains → Add:

```text
licence.leveragefx.co
```

Render shows a hostname (often `*.onrender.com`).

## 5. DNS at your registrar
```text
Type:  CNAME
Host:  licence
Value: <hostname Render shows for aegis-licence>
TTL:   300
```

Verify:
```text
https://licence.leveragefx.co/healthz  →  {"status":"ok"}
https://licence.leveragefx.co/dashboard/
```

Onrender.com URL remains a fallback; customers/EA should use `licence.leveragefx.co`.
