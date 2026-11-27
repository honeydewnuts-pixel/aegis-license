"""Owner command line. Runs on the server shell (or locally against a copy of the database).
There is deliberately NO admin web endpoint.

  python -m licence_service.admin newkey
  python -m licence_service.admin issue --serial AEG-TEST-0001 --plan ANNUAL --expiry 20270131 --features HOURFILTER \
         --max-accounts 1 --max-devices 1 --slots 5 --min-version 2.0.1 --login 0 --device '*' --test
        (asks for the activation password without showing it; prints the licence key once)
  python -m licence_service.admin revoke  --serial AEG-TEST-0001
  python -m licence_service.admin suspend --serial AEG-TEST-0001
  python -m licence_service.admin reactivate --serial AEG-TEST-0001
  python -m licence_service.admin expire  --serial AEG-TEST-0001          (sets expiry to yesterday)
  python -m licence_service.admin renew   --serial AEG-TEST-0001 --expiry 20280131
  python -m licence_service.admin unbind  --serial AEG-TEST-0001          (clears account/device bindings)
  python -m licence_service.admin show    --serial AEG-TEST-0001          (bindings shown masked)
  python -m licence_service.admin list
  python -m licence_service.admin backup  --to /path/backup.db            (consistent online copy)
Needs AEGIS_VENDOR_KEY_HEX and AEGIS_LICENCE_DB_PATH in the environment."""
import argparse, datetime, getpass, hashlib, hmac, re, secrets, sqlite3, sys, time
from .config import Config
from .storage import Storage


def licence_key(key, a, password):
    """Same format and signature that CLicenseManager::ValidateKey() verifies in the EA."""
    payload = '|'.join([a.serial, str(a.login), a.device, a.expiry, a.plan, a.features, str(a.slots), a.min_version])
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    return payload + '|' + hmac.new(key, (payload + '|' + pw_hash).encode(), hashlib.sha256).hexdigest()[:32]


def mask(v):
    return '****' + v[-3:] if len(v) > 3 else '****'


def main(argv=None):
    p = argparse.ArgumentParser(prog='licence_service.admin'); sp = p.add_subparsers(dest='cmd', required=True)
    sp.add_parser('newkey')
    i = sp.add_parser('issue')
    i.add_argument('--serial', required=True); i.add_argument('--plan', required=True, choices=['LIFETIME', 'MONTHLY', 'ANNUAL', 'ENTERPRISE'])
    i.add_argument('--expiry', required=True); i.add_argument('--features', default='HOURFILTER')
    i.add_argument('--max-accounts', type=int, default=1); i.add_argument('--max-devices', type=int, default=1)
    i.add_argument('--slots', type=int, default=5); i.add_argument('--min-version', default='2.0.1')
    i.add_argument('--login', default='0'); i.add_argument('--device', default='*'); i.add_argument('--test', action='store_true')
    i.add_argument('--password-stdin', action='store_true', help='read the activation password from stdin (for scripts)')
    for c in ('revoke', 'suspend', 'reactivate', 'expire', 'unbind', 'show'):
        sp.add_parser(c).add_argument('--serial', required=True)
    r = sp.add_parser('renew'); r.add_argument('--serial', required=True); r.add_argument('--expiry', required=True)
    sp.add_parser('list')
    b = sp.add_parser('backup'); b.add_argument('--to', required=True)
    a = p.parse_args(argv)

    if a.cmd == 'newkey':
        print('New vendor key (store it ONLY as the AEGIS_VENDOR_KEY_HEX secret and in your offline backup):')
        print(secrets.token_hex(32)); return 0
    cfg = Config(); db = Storage(cfg.db_path); now = int(time.time())
    if a.cmd == 'issue':
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{2,39}', a.serial): sys.exit('serial: letters, digits, dashes, 3-40 chars')
        if a.expiry != 'LIFETIME' and not re.fullmatch(r'\d{8}', a.expiry): sys.exit('expiry: LIFETIME or YYYYMMDD')
        if not re.fullmatch(r'\d+\.\d+\.\d+', a.min_version): sys.exit('min-version: like 2.0.1')
        if a.device != '*' and not re.fullmatch(r'[0-9a-f]{16}', a.device): sys.exit('device: * or the 16-hex id shown by the EA')
        pw = sys.stdin.readline().rstrip('\n') if a.password_stdin else getpass.getpass('Activation password (not shown): ')
        if len(pw) < 10: sys.exit('activation password must be at least 10 characters')
        with db.transaction() as c:
            if Storage.get_licence(c, a.serial): sys.exit('serial already exists')
            c.execute('INSERT INTO licences VALUES(?,?,?,?,?,?,?,?,?,?,?)', (a.serial, a.plan, 'OK', a.expiry, a.features, a.max_accounts,
                      a.max_devices, a.min_version, 1 if a.test else 0, now, now))
            Storage.audit(c, 'ISSUE', None, None, 'OK', 'test licence' if a.test else 'licence issued')
        print('Licence key (give it to the customer with the password; it is not stored on the server):')
        print(licence_key(cfg.vendor_key, a, pw)); return 0
    if a.cmd == 'list':
        with db.transaction() as c:
            for row in c.execute('SELECT serial,plan,status,expiry,max_accounts,max_devices,is_test FROM licences ORDER BY serial'):
                print(dict(row))
        return 0
    if a.cmd == 'backup':
        src = sqlite3.connect(cfg.db_path); dst = sqlite3.connect(a.to); src.backup(dst); dst.close(); src.close()
        print('backup written to', a.to); return 0
    with db.transaction() as c:
        lic = Storage.get_licence(c, a.serial)
        if not lic: sys.exit('serial not found')
        if a.cmd == 'show':
            print(dict(lic))
            for row in c.execute('SELECT kind,value,first_seen,last_seen FROM bindings WHERE serial=?', (a.serial,)):
                print(row['kind'], mask(row['value']), datetime.datetime.utcfromtimestamp(row['last_seen']).isoformat() + 'Z')
            return 0
        if a.cmd in ('revoke', 'suspend', 'reactivate'):
            st = {'revoke': 'REVOKED', 'suspend': 'SUSPENDED', 'reactivate': 'OK'}[a.cmd]
            c.execute('UPDATE licences SET status=?, updated_at=? WHERE serial=?', (st, now, a.serial))
        elif a.cmd == 'expire':
            y = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y%m%d')
            c.execute('UPDATE licences SET expiry=?, updated_at=? WHERE serial=?', (y, now, a.serial))
        elif a.cmd == 'renew':
            if not re.fullmatch(r'\d{8}', a.expiry): sys.exit('expiry: YYYYMMDD')
            c.execute('UPDATE licences SET expiry=?, updated_at=? WHERE serial=?', (a.expiry, now, a.serial))
        elif a.cmd == 'unbind':
            c.execute('DELETE FROM bindings WHERE serial=?', (a.serial,))
        Storage.audit(c, a.cmd.upper(), None, None, None, 'owner command')
    print(a.cmd, 'done'); return 0


if __name__ == '__main__':
    sys.exit(main())
