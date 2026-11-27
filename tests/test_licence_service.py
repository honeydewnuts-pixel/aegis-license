"""Licence service tests. Mock vendor key and temporary databases only; no network beyond 127.0.0.1.
Run from 04_Licence_Service:  python -m unittest -v tests.test_licence_service"""
import hashlib, hmac, io, json, os, secrets, sqlite3, sys, tempfile, threading, time, unittest, urllib.parse, urllib.request
from wsgiref.simple_server import make_server, WSGIRequestHandler
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, '..'))
from licence_service.config import Config, ConfigError
from licence_service.storage import Storage
from licence_service.app import LicenceApp
from licence_service import admin, core

MOCK_KEY = secrets.token_hex(32)          # generated per run; never a real key


def env(db, **kw):
    e = {'AEGIS_VENDOR_KEY_HEX': MOCK_KEY, 'AEGIS_LICENCE_DB_PATH': db, 'AEGIS_REQUIRE_HTTPS': 'true'}
    e.update(kw); return e


def add_licence(db, serial='AEG-T-0001', status='OK', expiry='20991231', max_accounts=1, max_devices=1, min_version='2.0.1'):
    s = Storage(db)
    with s.transaction() as c:
        c.execute('INSERT INTO licences VALUES(?,?,?,?,?,?,?,?,?,?,?)', (serial, 'ANNUAL', status, expiry, 'HOURFILTER', max_accounts, max_devices, min_version, 1, 0, 0))


def call(app, form=None, method='POST', path='/aegis/licence', proto='https', ctype='application/x-www-form-urlencoded', ip='10.0.0.1', body=None):
    raw = body if body is not None else urllib.parse.urlencode(form or {}).encode()
    environ = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'CONTENT_TYPE': ctype, 'CONTENT_LENGTH': str(len(raw)),
               'wsgi.input': io.BytesIO(raw), 'HTTP_X_FORWARDED_PROTO': proto, 'REMOTE_ADDR': ip, 'wsgi.url_scheme': 'http'}
    out = {}
    def sr(status, headers): out['status'] = int(status.split()[0]); out['headers'] = dict(headers)
    out['body'] = b''.join(app(environ, sr)).decode()
    return out


def req(serial='AEG-T-0001', login='12345678', device='0123456789abcdef', version='2.0.1', nonce=None):
    return dict(serial=serial, login=login, device=device, version=version, nonce=nonce or secrets.token_hex(8))


def ea_verify(reply, serial, nonce, key_hex=MOCK_KEY):
    """Exactly what CLicenseManager::OnlineCheck() does with the reply."""
    p = reply.strip().split('|')
    if len(p) != 5 or p[1] != serial or p[3] != nonce: return None
    expect = hmac.new(bytes.fromhex(key_hex), '|'.join(p[:4]).encode(), hashlib.sha256).hexdigest()
    return p[0] if hmac.compare_digest(expect, p[4].lower()) else 'NOT_AUTHENTIC'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.db = os.path.join(self.tmp.name, 'lic.db')
        self.app = LicenceApp(Config(env(self.db)))

    def tearDown(self):
        self.tmp.cleanup()


class TestConfig(unittest.TestCase):
    def test_missing_key_refuses_start(self):
        with self.assertRaises(ConfigError): Config({'AEGIS_LICENCE_DB_PATH': 'x'})

    def test_public_dev_key_refused(self):
        with self.assertRaises(ConfigError): Config({'AEGIS_VENDOR_KEY_HEX': b'AGESIS_DEV_4SEOTCSFEESCREWCTEBST'.hex()})

    def test_weak_and_malformed_keys_refused(self):
        for k in ('00' * 32, 'zz' * 32, 'ab' * 10):
            with self.assertRaises(ConfigError): Config({'AEGIS_VENDOR_KEY_HEX': k})

    def test_repr_hides_key(self):
        self.assertNotIn(MOCK_KEY, repr(Config(env('x.db'))))


class TestResponses(Base):
    def test_ok_signed_exactly_as_ea_expects(self):
        add_licence(self.db); r = req(); out = call(self.app, r)
        self.assertEqual(out['status'], 200); self.assertEqual(ea_verify(out['body'], r['serial'], r['nonce']), 'OK')
        self.assertEqual(out['body'].split('|')[2], '20991231')

    def test_wrong_key_is_not_authentic(self):
        add_licence(self.db); r = req(); out = call(self.app, r)
        self.assertEqual(ea_verify(out['body'], r['serial'], r['nonce'], secrets.token_hex(32)), 'NOT_AUTHENTIC')

    def test_unknown(self):
        r = req(serial='NOPE-1'); out = call(self.app, r)
        self.assertEqual(ea_verify(out['body'], r['serial'], r['nonce']), 'UNKNOWN')

    def test_expired(self):
        add_licence(self.db, expiry='20200101'); r = req()
        self.assertEqual(ea_verify(call(self.app, r)['body'], r['serial'], r['nonce']), 'EXPIRED')

    def test_revoked_and_suspended(self):
        add_licence(self.db, serial='AEG-R', status='REVOKED'); add_licence(self.db, serial='AEG-S', status='SUSPENDED')
        r1, r2 = req(serial='AEG-R'), req(serial='AEG-S')
        self.assertEqual(ea_verify(call(self.app, r1)['body'], 'AEG-R', r1['nonce']), 'REVOKED')
        self.assertEqual(ea_verify(call(self.app, r2)['body'], 'AEG-S', r2['nonce']), 'SUSPENDED')

    def test_account_mismatch(self):
        add_licence(self.db); a = req(login='111'); b = req(login='222')
        self.assertEqual(ea_verify(call(self.app, a)['body'], a['serial'], a['nonce']), 'OK')
        self.assertEqual(ea_verify(call(self.app, b, ip='10.0.0.2')['body'], b['serial'], b['nonce']), 'SUSPENDED')
        c = req(login='111'); self.assertEqual(ea_verify(call(self.app, c, ip='10.0.0.3')['body'], c['serial'], c['nonce']), 'OK')

    def test_device_mismatch(self):
        add_licence(self.db); a = req(device='aaaaaaaaaaaaaaaa'); b = req(device='bbbbbbbbbbbbbbbb')
        self.assertEqual(ea_verify(call(self.app, a)['body'], a['serial'], a['nonce']), 'OK')
        self.assertEqual(ea_verify(call(self.app, b)['body'], b['serial'], b['nonce']), 'SUSPENDED')

    def test_old_version_blocked(self):
        add_licence(self.db, min_version='2.0.1'); r = req(version='2.0.0')
        self.assertEqual(ea_verify(call(self.app, r)['body'], r['serial'], r['nonce']), 'SUSPENDED')

    def test_nonce_echoed_so_old_replies_cannot_be_replayed(self):
        add_licence(self.db); r = req(); body = call(self.app, r)['body']
        self.assertIsNone(ea_verify(body, r['serial'], secrets.token_hex(8)))

    def test_reply_contains_no_trading_instruction(self):
        add_licence(self.db); r = req(); p = call(self.app, r)['body'].split('|')
        self.assertIn(p[0], core.STATUSES); self.assertEqual(len(p), 5)


class TestValidationAndLimits(Base):
    def test_bad_inputs_rejected_unsigned(self):
        add_licence(self.db)
        for bad in (dict(req(), login='12a'), dict(req(), device='XYZ'), dict(req(), version='2.0'), dict(req(), nonce='zz'), dict(req(), serial='a')):
            out = call(self.app, bad); self.assertEqual(out['status'], 400); self.assertNotIn('|', out['body'])
        r = req(); del r['nonce']; self.assertEqual(call(self.app, r)['status'], 400)

    def test_duplicate_field_rejected(self):
        body = (urllib.parse.urlencode(req()) + '&login=999').encode()
        self.assertEqual(call(self.app, body=body)['status'], 400)

    def test_oversized_body(self):
        self.assertEqual(call(self.app, body=b'a=' + b'x' * 2000)['status'], 413)

    def test_wrong_method_path_type_and_http(self):
        self.assertEqual(call(self.app, req(), method='GET')['status'], 405)
        self.assertEqual(call(self.app, req(), path='/admin')['status'], 404)
        self.assertEqual(call(self.app, req(), ctype='application/json')['status'], 415)
        self.assertEqual(call(self.app, req(), proto='http')['status'], 403)

    def test_rate_limit_per_ip(self):
        add_licence(self.db); app = LicenceApp(Config(env(self.db, AEGIS_RATE_LIMIT_PER_IP_PER_MIN='3')))
        codes = [call(app, req(), ip='9.9.9.9')['status'] for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    def test_health_reveals_no_licence_data(self):
        add_licence(self.db); out = call(self.app, method='GET', path='/healthz')
        self.assertEqual(out['status'], 200); self.assertEqual(json.loads(out['body']), {'status': 'ok'})

    def test_logs_and_audit_hide_identifiers(self):
        add_licence(self.db); r = req(login='87654321')
        with self.assertLogs('aegis.licence', level='INFO') as lg:
            call(self.app, r)
        text = '\n'.join(lg.output)
        for secret in ('AEG-T-0001', '87654321', r['device'], '10.0.0.1', MOCK_KEY): self.assertNotIn(secret, text)
        rows = sqlite3.connect(self.db).execute('SELECT * FROM audit').fetchall()
        self.assertTrue(rows); self.assertNotIn('AEG-T-0001', str(rows)); self.assertNotIn('87654321', str(rows))


class TestConcurrencyAndPersistence(Base):
    def test_parallel_activations_never_exceed_limit(self):
        add_licence(self.db, max_accounts=2, max_devices=50)
        app = LicenceApp(Config(env(self.db, AEGIS_RATE_LIMIT_PER_SERIAL_PER_MIN='1000', AEGIS_RATE_LIMIT_PER_IP_PER_MIN='1000')))
        results = []; lock = threading.Lock()
        def worker(i):
            r = req(login=str(1000 + i), device=f'{i:016x}')
            st = ea_verify(call(app, r, ip=f'10.1.0.{i}')['body'], r['serial'], r['nonce'])
            with lock: results.append(st)
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(results.count('OK'), 2); self.assertEqual(results.count('SUSPENDED'), 23)
        n = sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM bindings WHERE kind='login'").fetchone()[0]
        self.assertEqual(n, 2)

    def test_bindings_survive_restart(self):
        add_licence(self.db); a = req(login='111'); call(self.app, a)
        app2 = LicenceApp(Config(env(self.db)))                 # new process equivalent
        b = req(login='222'); self.assertEqual(ea_verify(call(app2, b)['body'], b['serial'], b['nonce']), 'SUSPENDED')
        c = req(login='111'); self.assertEqual(ea_verify(call(app2, c)['body'], c['serial'], c['nonce']), 'OK')


class TestAdmin(Base):
    def run_admin(self, *args, stdin=None):
        old_env, old_in, old_out = dict(os.environ), sys.stdin, sys.stdout
        os.environ.update(env(self.db)); sys.stdin = io.StringIO(stdin or ''); sys.stdout = io.StringIO()
        try:
            admin.main(list(args)); return sys.stdout.getvalue()
        finally:
            os.environ.clear(); os.environ.update(old_env); sys.stdin, sys.stdout = old_in, old_out

    def test_issue_key_matches_ea_validatekey_and_lifecycle(self):
        out = self.run_admin('issue', '--serial', 'AEG-TEST-0001', '--plan', 'ANNUAL', '--expiry', '20991231', '--test', '--password-stdin',
                             stdin='correct horse battery\n')
        key_line = out.strip().splitlines()[-1]; p = key_line.split('|')
        self.assertEqual(len(p), 9)
        payload = '|'.join(p[:8]); pw = hashlib.sha256(b'correct horse battery').hexdigest()
        self.assertEqual(p[8], hmac.new(bytes.fromhex(MOCK_KEY), (payload + '|' + pw).encode(), hashlib.sha256).hexdigest()[:32])
        self.assertNotIn('correct horse battery', out)
        r = req(serial='AEG-TEST-0001')
        self.assertEqual(ea_verify(call(self.app, r)['body'], r['serial'], r['nonce']), 'OK')
        self.run_admin('revoke', '--serial', 'AEG-TEST-0001'); r = req(serial='AEG-TEST-0001')
        self.assertEqual(ea_verify(call(self.app, r)['body'], r['serial'], r['nonce']), 'REVOKED')
        self.run_admin('reactivate', '--serial', 'AEG-TEST-0001'); self.run_admin('expire', '--serial', 'AEG-TEST-0001')
        r = req(serial='AEG-TEST-0001'); self.assertEqual(ea_verify(call(self.app, r)['body'], r['serial'], r['nonce']), 'EXPIRED')
        shown = self.run_admin('show', '--serial', 'AEG-TEST-0001'); self.assertNotIn('12345678', shown)
        backup = os.path.join(self.tmp.name, 'b.db'); self.run_admin('backup', '--to', backup)
        self.assertEqual(sqlite3.connect(backup).execute('SELECT COUNT(*) FROM licences').fetchone()[0], 1)

    def test_short_password_refused(self):
        with self.assertRaises(SystemExit):
            self.run_admin('issue', '--serial', 'AEG-X1', '--plan', 'ANNUAL', '--expiry', '20991231', '--password-stdin', stdin='short\n')


class TestRealHttp(Base):
    def test_end_to_end_over_local_http(self):
        add_licence(self.db)
        class Quiet(WSGIRequestHandler):
            def log_message(self, *a): pass
        app = LicenceApp(Config(env(self.db, AEGIS_REQUIRE_HTTPS='false')))
        srv = make_server('127.0.0.1', 0, app, handler_class=Quiet); port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
        try:
            r = req(); data = urllib.parse.urlencode(r).encode()
            resp = urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/aegis/licence', data=data,
                                          headers={'Content-Type': 'application/x-www-form-urlencoded'}), timeout=5)
            self.assertEqual(ea_verify(resp.read().decode(), r['serial'], r['nonce']), 'OK')
            h = urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=5); self.assertEqual(h.status, 200)
        finally:
            srv.shutdown()


if __name__ == '__main__':
    unittest.main(verbosity=2)
