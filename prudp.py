class PRUDPPacket:
    def __init__(self):
        self.data = bytearray
        self.version = int
        self.source = int
        self.destination = int
        self.packet_type = int
        self.flags = int
        self.session_id = int
        self.fragment_id = int
        self.signature = int

    def get_version(self) -> int: return self.version
    def get_source(self) -> int: return self.source
    def get_destination(self) -> int: return self.destination
    def get_packet_type(self) -> int: return self.packet_type
    def get_flags(self) -> int: return self.flags

    def set_version(self, version: int): self.version = version
    def set_source(self, source: int): self.source = source
    def set_destination(self, destination: int): self.destination = destination
    def set_packet_type(self, packet_type: int): self.packet_type = packet_type
    def set_flags(self, flags: int): self.flags = flags
    def has_flag(flags: int, flag: int) -> bool: return (flags & flag) != 0
    def add_flag(flags: int, flag: int) -> int: return flags | flag
    def clear_flag(flags: int, flag: int) -> int: return flags & ~flag


class PRUDPPacketV0(PRUDPPacket):
    def __init__(self):
        self.checksum_version = int

    

class PRUDPPacketV1(PRUDPPacket):
    def __init__(self):
        pass


class PRUDPPacketLite(PRUDPPacket):
    def __init__(self):
        pass


class PRUDPClient:
    def __init__(self):
        self.pid = int

    def get_pid(self) -> int: return self.pid
    def set_pid(self, pid: int): self.pid = pid


class PRUDPServer:
    def __init__(self):
        pass