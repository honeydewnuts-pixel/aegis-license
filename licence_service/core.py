"""Licence decision and signing. Produces exactly the reply the AEGIS EA parses in CLicenseManager::OnlineCheck():
    STATUS|SERIAL|EXPIRY|NONCE|SIG     SIG = hex HMAC-SHA256(vendor key, "STATUS|SERIAL|EXPIRY|NONCE")
STATUS is one of OK, REVOKED, EXPIRED, SUSPENDED, UNKNOWN. The service only answers "may this copy run";
it has no way to send trading instructions or change EA settings."""
import datetime, hashlib, hmac, re, time

SERIAL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{2,39}')
LOGIN_RE = re.compile(r'\d{1,20}')
DEVICE_RE = re.compile(r'[0-9a-f]{16}')
VERSION_RE = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}')
NONCE_RE = re.compile(r'[0-9a-f]{8,64}')
STATUSES = ('OK', 'REVOKED', 'EXPIRED', 'SUSPENDED', 'UNKNOWN')


def ref(value, key):
    """Short keyed hash used in logs instead of serials, logins, devices or IP addresses."""
    if not value:
        return '-'
    return hmac.new(key, ('ref:' + value).encode(), hashlib.sha256).hexdigest()[:10]


def version_num(v):
    a, b, c = (int(x) for x in v.split('.'))
    return a * 10000 + b * 100 + c


def sign(key, status, serial, expiry, nonce):
    body = f'{status}|{serial}|{expiry}|{nonce}'
    return body + '|' + hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def validate_request(form):
    """Returns (fields, error). Every field must be present, single-valued and well formed."""
    out = {}
    for name, rx in (('serial', SERIAL_RE), ('login', LOGIN_RE), ('device', DEVICE_RE), ('version', VERSION_RE), ('nonce', NONCE_RE)):
        vals = form.get(name, [])
        if len(vals) != 1 or not rx.fullmatch(vals[0]):
            return None, f'invalid or missing field: {name}'
        out[name] = vals[0]
    return out, ''


def decide(storage, key, req, ip, today=None, now=None):
    """Check-and-bind in one transaction. Returns (status, expiry, reason)."""
    today = today or datetime.datetime.utcnow().strftime('%Y%m%d')
    now = now or int(time.time())
    serial = req['serial']
    with storage.transaction() as c:
        lic = storage.get_licence(c, serial)
        if lic is None:
            status, expiry, reason = 'UNKNOWN', '', 'serial not registered'
        else:
            expiry = lic['expiry']
            if lic['status'] == 'REVOKED':
                status, reason = 'REVOKED', 'revoked by owner'
            elif lic['status'] == 'SUSPENDED':
                status, reason = 'SUSPENDED', 'suspended by owner'
            elif expiry != 'LIFETIME' and today > expiry:
                status, reason = 'EXPIRED', 'past expiry date'
            elif version_num(req['version']) < version_num(lic['min_version']):
                status, reason = 'SUSPENDED', 'EA version below licence minimum'
            else:
                status, reason = 'OK', 'valid'
                logins = storage.bound_values(c, serial, 'login')
                devices = storage.bound_values(c, serial, 'device')
                if req['login'] not in logins and len(logins) >= lic['max_accounts']:
                    status, reason = 'SUSPENDED', 'account limit reached'
                elif req['device'] not in devices and len(devices) >= lic['max_devices']:
                    status, reason = 'SUSPENDED', 'device limit reached'
                else:
                    storage.bind(c, serial, 'login', req['login'], now)
                    storage.bind(c, serial, 'device', req['device'], now)
        storage.audit(c, 'CHECK', ref(serial, key), ref(ip, key), status, reason)
    return status, expiry, reason
