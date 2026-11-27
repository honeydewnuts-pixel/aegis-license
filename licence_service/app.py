"""WSGI application. Run in production with:
    gunicorn licence_service.app:application --bind 0.0.0.0:$PORT --workers 1 --threads 4
One worker is required: SQLite file storage and the in-memory rate limiter live in one process.

Routes
  POST /aegis/licence   form: serial, login, device, version, nonce  -> text/plain signed reply
  GET  /healthz         -> {"status":"ok"} (no licence data)
Everything else -> 404. Errors never return signed data, so the EA treats them as "server unreachable"
(offline grace) rather than as a licence decision."""
import json, logging, threading, time
from urllib.parse import parse_qs
from .config import Config, ConfigError
from .storage import Storage
from . import core

log = logging.getLogger('aegis.licence')


class RateLimiter:
    """Sliding one-minute window per key. In-memory, per process."""
    def __init__(self):
        self.lock = threading.Lock(); self.hits = {}

    def allow(self, key, limit, now=None):
        now = now or time.time()
        with self.lock:
            q = [t for t in self.hits.get(key, []) if now - t < 60]
            ok = len(q) < limit
            if ok: q.append(now)
            self.hits[key] = q
            if len(self.hits) > 50000:          # bound memory
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 60}
            return ok


def _respond(start_response, code, body, ctype='text/plain; charset=utf-8'):
    reasons = {200: 'OK', 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
               411: 'Length Required', 413: 'Payload Too Large', 415: 'Unsupported Media Type', 429: 'Too Many Requests', 503: 'Service Unavailable'}
    data = body.encode() if isinstance(body, str) else body
    start_response(f'{code} {reasons.get(code, "Error")}', [('Content-Type', ctype), ('Content-Length', str(len(data))),
                                                           ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')])
    return [data]


class LicenceApp:
    def __init__(self, config=None, storage=None):
        self.cfg = config or Config()
        self.db = storage or Storage(self.cfg.db_path)
        self.rl = RateLimiter()

    def client_ip(self, environ):
        fwd = environ.get('HTTP_X_FORWARDED_FOR', '')
        return (fwd.split(',')[0].strip() if fwd else environ.get('REMOTE_ADDR', '')) or '-'

    def __call__(self, environ, start_response):
        path, method = environ.get('PATH_INFO', ''), environ.get('REQUEST_METHOD', '')
        if path == '/healthz':
            if method not in ('GET', 'HEAD'): return _respond(start_response, 405, 'method not allowed')
            try:
                self.db.health(); return _respond(start_response, 200, json.dumps({'status': 'ok'}), 'application/json')
            except Exception:
                log.exception('health check failed')
                return _respond(start_response, 503, json.dumps({'status': 'unavailable'}), 'application/json')
        if path != '/aegis/licence': return _respond(start_response, 404, 'not found')
        if method != 'POST': return _respond(start_response, 405, 'method not allowed')
        if self.cfg.require_https and environ.get('HTTP_X_FORWARDED_PROTO', environ.get('wsgi.url_scheme', '')) != 'https':
            return _respond(start_response, 403, 'https required')
        ip = self.client_ip(environ); key = self.cfg.vendor_key
        if not self.rl.allow('ip:' + ip, self.cfg.rate_per_ip_per_min):
            log.warning('rate_limited ip_ref=%s', core.ref(ip, key)); return _respond(start_response, 429, 'too many requests')
        ctype = environ.get('CONTENT_TYPE', '').split(';')[0].strip().lower()
        if ctype != 'application/x-www-form-urlencoded': return _respond(start_response, 415, 'form encoding required')
        try:
            n = int(environ.get('CONTENT_LENGTH') or '')
        except ValueError:
            return _respond(start_response, 411, 'length required')
        if n < 0 or n > self.cfg.max_body_bytes: return _respond(start_response, 413, 'request too large')
        raw = environ['wsgi.input'].read(n)
        try:
            form = parse_qs(raw.decode('utf-8', 'strict'), keep_blank_values=True, strict_parsing=False, max_num_fields=10)
        except (UnicodeDecodeError, ValueError):
            return _respond(start_response, 400, 'bad request')
        req, err = core.validate_request(form)
        if req is None:
            log.info('bad_request ip_ref=%s reason=%s', core.ref(ip, key), err); return _respond(start_response, 400, 'bad request')
        if not self.rl.allow('serial:' + req['serial'], self.cfg.rate_per_serial_per_min):
            log.warning('rate_limited serial_ref=%s', core.ref(req['serial'], key)); return _respond(start_response, 429, 'too many requests')
        try:
            status, expiry, reason = core.decide(self.db, key, req, ip)
        except Exception:
            log.exception('decision failed serial_ref=%s', core.ref(req['serial'], key))
            return _respond(start_response, 503, 'temporarily unavailable')
        log.info('licence_check serial_ref=%s ip_ref=%s status=%s reason=%s', core.ref(req['serial'], key), core.ref(ip, key), status, reason)
        return _respond(start_response, 200, core.sign(key, status, req['serial'], expiry, req['nonce']))


def _make():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        return LicenceApp()
    except ConfigError as e:
        log.error('configuration error: %s', e); raise


application = None
if __name__ != '__main__':
    import os
    if os.environ.get('AEGIS_VENDOR_KEY_HEX'):      # created lazily so tests can import without env
        application = _make()
