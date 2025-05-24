import hmac
import hashlib
import struct
import secrets
from datetime import datetime
try:
    from Crypto.Cipher import ARC4
except ImportError:
    ARC4 = None
from common import md5_hash, rc4

class KerberosCipher:
    def __init__(self, key):
        self.key = key

    def crypt(self, data):
        if ARC4 is not None:
            cipher = ARC4.new(self.key)
            return cipher.encrypt(data)
        else:
            return rc4(self.key, data)

    def encrypt(self, data):
        encrypted = self.crypt(data)
        mac = hmac.new(self.key, encrypted, hashlib.md5).digest()
        return encrypted + mac

    def decrypt(self, data):
        if not self.valid_hmac(data):
            raise ValueError("Kerberos HMAC validation failed")
        enc_part = data[:-16]
        return self.crypt(enc_part)

    def valid_hmac(self, data):
        enc_part = data[:-16]
        mac = data[-16:]
        calc_mac = hmac.new(self.key, enc_part, hashlib.md5).digest()
        return hmac.compare_digest(mac, calc_mac)

class KerberosTicket:
    def __init__(self, session_secret=None, pid=None, extra=None):
        self.session_secret = session_secret or b''
        self.pid = pid or 0
        self.extra = extra or b''

    def to_bytes(self):
        buf = struct.pack('<I', self.pid)
        buf += struct.pack('<I', len(self.session_secret)) + self.session_secret
        buf += struct.pack('<I', len(self.extra)) + self.extra
        return buf

    @classmethod
    def from_bytes(cls, data):
        offset = 0
        pid, = struct.unpack_from('<I', data, offset)
        offset += 4
        sk_len, = struct.unpack_from('<I', data, offset)
        offset += 4
        session_secret = data[offset:offset+sk_len]
        offset += sk_len
        ex_len, = struct.unpack_from('<I', data, offset)
        offset += 4
        extra = data[offset:offset+ex_len]
        return cls(session_secret, pid, extra)

    def encrypt(self, key):
        cipher = KerberosCipher(key)
        return cipher.encrypt(self.to_bytes())

    @classmethod
    def decrypt(cls, key, data):
        cipher = KerberosCipher(key)
        decrypted = cipher.decrypt(data)
        return cls.from_bytes(decrypted)

class KerberosTicketInternal:
    def __init__(self, timestamp=None, user_pid=None, session_key=None):
        self.timestamp = timestamp or datetime.utcnow()
        self.user_pid = user_pid or 0
        self.session_key = session_key or b''

    def to_bytes(self):
        ts = int(self.timestamp.timestamp())
        buf = struct.pack('<Q', ts)
        buf += struct.pack('<I', self.user_pid)
        buf += struct.pack('<I', len(self.session_key)) + self.session_key
        return buf

    def encrypt(self, key, version=0):
        payload = self.to_bytes()
        if version == 1:
            random_key = secrets.token_bytes(16)
            final_key = md5_hash(key + random_key)
            cipher = KerberosCipher(final_key)
            enc_data = cipher.encrypt(payload)
            return struct.pack('<I', len(random_key)) + random_key + struct.pack('<I', len(enc_data)) + enc_data
        else:
            cipher = KerberosCipher(key)
            return cipher.encrypt(payload)

    @classmethod
    def decrypt(cls, key, data, version=0):
        if version == 1:
            rk_len = struct.unpack_from('<I', data, 0)[0]
            offset = 4
            random_key = data[offset:offset+rk_len]
            offset += rk_len
            ed_len = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            enc_data = data[offset:offset+ed_len]
            key = md5_hash(key + random_key)
            data = enc_data
        cipher = KerberosCipher(key)
        plain = cipher.decrypt(data)
        ts_val = struct.unpack_from('<Q', plain, 0)[0]
        offset = 8
        user_pid = struct.unpack_from('<I', plain, offset)[0]
        offset += 4
        sk_len = struct.unpack_from('<I', plain, offset)[0]
        offset += 4
        session_key = plain[offset:offset+sk_len]
        timestamp = datetime.utcfromtimestamp(ts_val)
        return cls(timestamp, user_pid, session_key)

def derive_kerberos_key(pid, password):
    val = password
    for _ in range(65000 + (pid % 1024)):
        val = md5_hash(val)
    return val