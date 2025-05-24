import re
import hashlib
from streams import StreamIn
from datetime import datetime

SYN_PACKET = 0
CONNECT_PACKET = 1
DATA_PACKET = 2
DISCONNECT_PACKET = 3
PING_PACKET = 4
USER_PACKET = 5

FLAG_ACK = 1
FLAG_RELIABLE = 2
FLAG_NEED_ACK = 4
FLAG_HAS_SIZE = 8
FLAG_MULTI_ACK = 0x200

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(char ^ k)
    return bytes(out)

def md5_hash(data):
    return hashlib.md5(data).digest()


class DateTime:
    __slots__ = ['_raw']

    def __init__(self, raw=0):
        self._raw = int(raw)

    @classmethod
    def from_ymdhms(cls, y, m, d, h, mi, s):
        val = (
            (int(y)   << 26) |
            (int(m)   << 22) |
            (int(d)   << 17) |
            (int(h)   << 12) |
            (int(mi)  << 6)  |
            (int(s))
        )
        return cls(val)

    @classmethod
    def from_datetime(cls, dt):
        return cls.from_ymdhms(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    @classmethod
    def now(cls):
        return cls.from_datetime(datetime.now())

    @classmethod
    def from_timestamp(cls, ts):
        dt = datetime.fromtimestamp(ts)
        return cls.from_datetime(dt)

    @property
    def raw(self):
        return self._raw

    def to_ymdhms(self):
        v = self._raw
        y = (v >> 26) & 0x3F
        m = (v >> 22) & 0xF
        d = (v >> 17) & 0x1F
        h = (v >> 12) & 0x1F
        mi = (v >> 6) & 0x3F
        s = v & 0x3F
        return (y, m, d, h, mi, s)

    def __int__(self):
        return self._raw

    def __repr__(self):
        y, m, d, h, mi, s = self.to_ymdhms()
        return f"<DateTime {y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} ({self._raw})>"

    def to_datetime(self):
        y, m, d, h, mi, s = self.to_ymdhms()
        return datetime(y, m, d, h, mi, s)


class StationURL:
    _field_map = {
        "CID": "cid",
        "PID": "pid",
        "RVCID": "rvcid",
        "PRID": "prid",
        "sid": "sid",
        "address": "address",
        "port": "port",
        "stream": "stream",
        "type": "transport_type",
        "natm": "natm",
        "natf": "natf",
        "upnp": "upnp",
        "pmp": "pmp",
        "probeinit": "probeinit"
    }
    _reverse_field_map = {v: k for k, v in _field_map.items()}

    __slots__ = ["scheme", "_fields"]

    def __init__(self, urlstr=None, **kwargs):
        self.scheme = None
        self._fields = dict.fromkeys(self._field_map.values(), "")

        if urlstr:
            self.parse(urlstr)
        for k, v in kwargs.items():
            if k in self._fields:
                self._fields[k] = v

    def __getitem__(self, key):
        return self._fields.get(key, "")

    def __setitem__(self, key, value):
        if key in self._fields:
            self._fields[key] = value

    def __repr__(self):
        return f"<StationURL {self.to_string()}>"

    def parse(self, urlstr):
        m = re.match(r'^([a-zA-Z0-9_]+):/(.*)$', urlstr.strip())
        if not m:
            raise ValueError("Invalid StationURL format")
        self.scheme = m.group(1)
        fields = m.group(2).split(";")
        for pair in fields:
            if '=' in pair:
                k, v = pair.split("=", 1)
                k_norm = self._field_map.get(k, k.lower())
                if k_norm in self._fields:
                    self._fields[k_norm] = v

    def to_string(self):
        parts = []
        for key in self._fields:
            value = self._fields[key]
            if value:
                k_out = self._reverse_field_map.get(key, key)
                parts.append(f"{k_out}={value}")
        return f"{self.scheme}:/" + ";".join(parts)

    def __getattr__(self, attr):
        if attr in self._fields:
            return self._fields[attr]
        raise AttributeError(f"'StationURL' object has no attribute '{attr}'")

    def __setattr__(self, attr, value):
        if attr in ("scheme", "_fields"):
            super().__setattr__(attr, value)
        elif attr in self._fields:
            self._fields[attr] = value
        else:
            raise AttributeError(f"'StationURL' object has no attribute '{attr}'")

    @classmethod
    def from_fields(cls, scheme, **fields):
        obj = cls()
        obj.scheme = scheme
        for k, v in fields.items():
            if k in obj._fields:
                obj._fields[k] = v
        return obj

    @classmethod
    def new(cls, urlstr):
        return cls(urlstr)


class ResultRange:
    __slots__ = ("offset", "length", "structure")

    def __init__(self, offset=0, length=0, structure=None):
        self.offset = offset
        self.length = length
        self.structure = structure

    @classmethod
    def from_stream(cls, stream: StreamIn):
        offset = stream.u32()
        length = stream.u32()
        return cls(offset=offset, length=length)

    @classmethod
    def new(cls):
        return cls()

    def __repr__(self):
        return f"<ResultRange offset={self.offset} length={self.length}>"
    

class DummyCompression:
    def compress(self, data: bytes) -> bytes: return data
    def decompress(self, data: bytes) -> bytes: return data


class ZLibCompression:
    def compress(self, data: bytes) -> bytes: return data
    def decompress(self, data: bytes) -> bytes: return data


class AuthenticationUser:
    def __init__(self, pid: int, username: str, password: str):
        self.pid = pid
        self.username = username
        self.password = password