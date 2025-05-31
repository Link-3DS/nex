from enum import IntFlag, IntEnum

class PRUDPFlags(IntFlag):
    ACK        = 0x001
    RELIABLE   = 0x002
    NEED_ACK   = 0x004
    HAS_SIZE   = 0x008
    MULTI_ACK  = 0x200

class PRUDPTypes(IntEnum):
    SYN         = 0
    CONNECT     = 1
    DATA        = 2
    DISCONNECT  = 3
    PING        = 4
    USER        = 5


class StationURL:
    allowed_keys = {
        "scheme", "address", "port", "stream", "sid",
        "CID", "PID", "type", "RVCID", "natm", "natf",
        "upnp", "pmp", "probeinit", "PRID"
    }

    def __init__(self, **kwargs):
        self.scheme = kwargs.get("scheme", "")
        self.params = {}

        for key in self.allowed_keys - {"scheme"}:
            self.params[key] = kwargs.get(key)

    def encode_to_string(self):
        parts = []
        for key in self.allowed_keys:
            if key == "scheme":
                continue
            value = self.params.get(key)
            if value:
                parts.append(f"{key}={value}")
        return f"{self.scheme}:/" + ";".join(parts)

    def from_string(self, url_str):
        if ":/" not in url_str:
            raise ValueError("Invalid StationURL format")
        
        self.scheme, rest = url_str.split(":/", 1)
        for segment in rest.split(";"):
            if "=" in segment:
                key, value = segment.split("=", 1)
                if key in self.allowed_keys:
                    self.params[key] = value

    def __getattr__(self, name):
        if name in self.params:
            return self.params[name]
        raise AttributeError(f"'StationURL' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name in {"scheme", "params", "allowed_keys"}:
            super().__setattr__(name, value)
        elif name in self.allowed_keys:
            self.params[name] = value
        else:
            raise AttributeError(f"'StationURL' object has no attribute '{name}'")

    def __repr__(self):
        return f"<StationURL {self.encode_to_string()}>"
