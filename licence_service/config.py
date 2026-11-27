"""Configuration from environment variables only. Nothing secret is ever stored in code or files."""
import os, re

# The developer default key that shipped in AEGIS 2.0.0 tools. It is public, so the service refuses it.
_PUBLIC_DEV_KEY = b'AGESIS_DEV_4SEOTCSFEESCREWCTEBST'


class ConfigError(Exception):
    pass


class Config:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        key_hex = (env.get('AEGIS_VENDOR_KEY_HEX') or '').strip()
        if not key_hex:
            raise ConfigError('AEGIS_VENDOR_KEY_HEX is not set. The service will not start without its secret key.')
        if not re.fullmatch(r'[0-9a-fA-F]{64,128}', key_hex):
            raise ConfigError('AEGIS_VENDOR_KEY_HEX must be 64-128 hexadecimal characters (32-64 bytes).')
        key = bytes.fromhex(key_hex)
        if key == _PUBLIC_DEV_KEY or len(set(key)) < 8:
            raise ConfigError('AEGIS_VENDOR_KEY_HEX is a known or weak key. Generate a new one.')
        self.vendor_key = key
        self.db_path = env.get('AEGIS_LICENCE_DB_PATH', 'licences.db')
        self.require_https = env.get('AEGIS_REQUIRE_HTTPS', 'true').lower() in ('1', 'true', 'yes')
        self.rate_per_ip_per_min = int(env.get('AEGIS_RATE_LIMIT_PER_IP_PER_MIN', '30'))
        self.rate_per_serial_per_min = int(env.get('AEGIS_RATE_LIMIT_PER_SERIAL_PER_MIN', '20'))
        self.max_body_bytes = 1024
        if self.rate_per_ip_per_min < 1 or self.rate_per_serial_per_min < 1:
            raise ConfigError('Rate limits must be >= 1')

    def __repr__(self):  # never print the key
        return f'Config(db_path={self.db_path!r}, require_https={self.require_https}, vendor_key=<hidden>)'
