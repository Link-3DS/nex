import struct

class RMCRequest:
    FMT_BASE = "<I"
    FMT_BODY = "<BII"
    FMT_CUSTOM = "<H"
    HEADER_SIZE = 13

    def __init__(self, protocol=0, cid=0, call=0, method=0, params=b""):
        self.fields = {
            "protocol": protocol,
            "custom": cid,
            "call": call,
            "method": method,
            "params": params
        }

    def __getitem__(self, k): return self.fields[k]
    def __setitem__(self, k, v): self.fields[k] = v

    @staticmethod
    def from_bytes(byts):
        if len(byts) < RMCRequest.HEADER_SIZE:
            raise ValueError("Data too short")
        sz = struct.unpack_from("<I", byts, 0)[0]
        if sz != len(byts) - 4:
            raise ValueError("Size mismatch")

        pos = 4
        proto_raw = byts[pos]
        proto = proto_raw ^ 0x80
        pos += 1

        request = RMCRequest()
        request["protocol"] = proto

        if proto == 0x7F:
            request["custom"] = struct.unpack_from("<H", byts, pos)[0]
            pos += 2
        else:
            request["custom"] = 0

        request["call"] = struct.unpack_from("<I", byts, pos)[0]
        pos += 4
        request["method"] = struct.unpack_from("<I", byts, pos)[0]
        pos += 4

        request["params"] = byts[pos:]
        return request

    def to_bytes(self):
        out = bytearray()
        proto_byte = self["protocol"] | 0x80
        body = bytearray([proto_byte])
        if self["protocol"] == 0x7F:
            body += struct.pack("<H", self["custom"])
        body += struct.pack("<I", self["call"])
        body += struct.pack("<I", self["method"])
        if self["params"]:
            body += self["params"]

        total_size = len(body)
        out += struct.pack("<I", total_size)
        out += body
        return bytes(out)

    def get_protocol(self): return self["protocol"]
    def get_custom(self): return self["custom"]
    def get_call(self): return self["call"]
    def get_method(self): return self["method"]
    def get_params(self): return self["params"]
    def set_protocol(self, v): self["protocol"] = v
    def set_custom(self, v): self["custom"] = v
    def set_call(self, v): self["call"] = v
    def set_method(self, v): self["method"] = v
    def set_params(self, v): self["params"] = v

    @classmethod
    def new_blank(cls):
        return cls()

class RMCResponse:
    def __init__(self, protocol=0, cid=0, call=0, method=0, data=b"", ok=True, err=0):
        self.data = {
            "protocol": protocol,
            "custom": cid,
            "call": call,
            "method": method,
            "success": 1 if ok else 0,
            "resp_data": data,
            "error": err
        }

    def set_success(self, meth, data):
        self.data["success"] = 1
        self.data["method"] = meth
        self.data["resp_data"] = data
        self.data["error"] = 0

    def set_error(self, err_code):
        self.data["success"] = 0
        if not (err_code & 0x10000000):
            err_code |= 0x10000000
        self.data["error"] = err_code

    def to_bytes(self):
        out = bytearray()
        out.append(self.data["protocol"])
        if self.data["protocol"] == 0x7F:
            out += struct.pack("<H", self.data["custom"])
        out.append(self.data["success"])

        if self.data["success"] == 1:
            out += struct.pack("<I", self.data["call"])
            out += struct.pack("<I", self.data["method"] | 0x8000)
            if self.data["resp_data"]:
                out += self.data["resp_data"]
        else:
            out += struct.pack("<I", self.data["error"])
            out += struct.pack("<I", self.data["call"])
        return bytes(out)

    @staticmethod
    def new(protocol, call):
        return RMCResponse(protocol=protocol, call=call)