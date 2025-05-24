import socket
import time
import os
import inspect
import threading
import multiprocessing
from typing import Dict
from common import SYN_PACKET, CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET, PING_PACKET, FLAG_ACK, FLAG_NEED_ACK, FLAG_RELIABLE, FLAG_HAS_SIZE, FLAG_MULTI_ACK

class PRUDPPacket:
    def __init__(self):
        self.data = bytearray()
        self.version = int
        self.source = int
        self.destination = int
        self.packet_type = int
        self.flags = int
        self.fragment_id = int
        self.connection_signature = bytearray()
        self.payload = bytearray()


class PRUDPPacketV0(PRUDPPacket):
    def __init__(self):
        self.checksum = int


class PRUDPPacketV1(PRUDPPacket):
    def __init__(self):
        self.magic = bytearray()
        self.substream_id = int
        self.supported_functions = int
        self.initial_sequence_id = int
        self.max_substream_id = int


class PRUDPClient:
    def __init__(self, address: socket.socket):
        self.address = address
        self.secure_key = bytearray
        self.session_id = int
        self.pid = int
        self.local_station_url = str
        self.connected = bool


class PRUDPServer(PRUDPClient):
    def __init__(self):
        super().__init__(None)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.generic_event_handles: Dict[str, list] = {}
        self.prudp_v0_event_handles: Dict[str, list] = {}
        self.prudp_v1_event_handles: Dict[str, list] = {}
        self.access_key = str
        self.prudp_version = int
        self.nex_version = int
        self.fragment_size = int
        self.kerberos_password = str
        self.kerberos_size = int
        self.kerberos_derivation = int
        self.kerberos_ticket = int
        self.clients: Dict[str, PRUDPClient] = {}

    def listen(self, address: str):
        udp_ip, udp_port = address.split(":")
        udp_port = int(udp_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((udp_ip, udp_port))

        self.socket = sock

        quit_event = threading.Event()

        def listen_datagram():
            err = None
            while err is None:
                try:
                    err = self.handle_socket_message()
                except Exception as e:
                    err = e
            quit_event.set()
            raise err

        num_threads = multiprocessing.cpu_count()
        for _ in range(num_threads):
            thread = threading.Thread(target=listen_datagram, daemon=True)
            thread.start()

        print(f"PRUDP Server listening on {udp_ip}:{udp_port}")
        self.emit("Listening", None)

        quit_event.wait()

    def handle_socket_message(self):
        buffer = bytearray(64000)

        sock = self.socket

        try:
            length, addr = sock.recvfrom_into(buffer)
        except Exception as err:
            return err

        discriminator = f"{addr[0]}:{addr[1]}"

        if discriminator not in self.clients:
            new_client = PRUDPClient(addr)
            self.clients[discriminator] = new_client

        client = self.clients[discriminator]

        data = buffer[:length]

        packet = PRUDPPacket()
        err = None
        if self.prudp_version == 0:
            try:
                packet = PRUDPPacketV0(data)
            except Exception as e:
                err = e
        else:
            try:
                packet = PRUDPPacketV1(data)
            except Exception as e:
                err = e

        if err is not None:
            return None

        if (packet.flags & FLAG_ACK) != 0 or (packet.flags & FLAG_MULTI_ACK) != 0:
            return None

        if (packet.flags & FLAG_NEED_ACK) != 0:
            if packet.packet_type != CONNECT_PACKET or (packet.packet_type == CONNECT_PACKET and len(packet.payload) <= 0):
                import threading
                threading.Thread(target=self.acknowledge_packet, args=(packet, None)).start()

        if packet.packet_type == SYN_PACKET:
            client.connected = True
            self.emit("Syn", packet)
        elif packet.packet_type == CONNECT_PACKET:
            # TODO
            # packet.sender().set_client_connection_signature(packet.connection_signature())
            self.emit("Connect", packet)
        elif packet.packet_type == DATA_PACKET:
            self.emit("Data", packet)
        elif packet.packet_type == DISCONNECT_PACKET:
            self.emit("Disconnect", packet)
            self.kick()
        elif packet.packet_type == PING_PACKET:
            self.emit("Ping", packet)

        self.emit("Packet", packet)

        return None
    
    def acknowledge_packet(self, packet: PRUDPPacket, payload: bytearray):
        ack_packet = PRUDPPacket()

        if self.prudp_version == 0:
            ack_packet = PRUDPPacketV0()
        else:
            ack_packet = PRUDPPacketV1()

        ack_packet.source = packet.destination
        ack_packet.destination = packet.source
        ack_packet.packet_type = packet.packet_type
        ack_packet.fragment_id = packet.fragment_id
        ack_packet.flags |= FLAG_ACK
        ack_packet.flags |= FLAG_HAS_SIZE

        if payload != None:
            ack_packet.payload = payload

        if self.prudp_version == 0:
            packet = PRUDPPacketV1()
            ack_packet = PRUDPPacketV1()

            ack_packet.version = 1
            ack_packet.substream_id = 0
            ack_packet.flags |= FLAG_HAS_SIZE

            if packet.packet_type == SYN_PACKET:
                server_connection_signature = os.urandom(16)
                # TODO
                # ack_packet.sender().set_server_connection_signature(server_connection_signature)
                ack_packet.supported_functions = packet.supported_functions
                ack_packet.max_substream_id = 0
                ack_packet.connection_signature = server_connection_signature

            if packet.packet_type == CONNECT_PACKET:
                ack_packet.connection_signature = bytes(16)
                ack_packet.supported_functions = packet.supported_functions
                ack_packet.initial_sequence_id = 10000
                ack_packet.max_substream_id = 0

            if packet.packet_type == DATA_PACKET:
                pass # TODO: Add this
    
    def emit(self, event: str, packet):
        handlers = self.generic_event_handles.get(event, [])
        for handler in handlers:
            threading.Thread(target=handler, args=(packet,)).start()

        if isinstance(packet, PRUDPPacketV0):
            handlers = self.prudp_v0_event_handles.get(event, [])
            for handler in handlers:
                threading.Thread(target=handler, args=(packet,)).start()

        if isinstance(packet, PRUDPPacketV1):
            handlers = self.prudp_v1_event_handles.get(event, [])
            for handler in handlers:
                threading.Thread(target=handler, args=(packet,)).start()

    def kick(self):
        packet = PRUDPPacket()
        client = PRUDPClient()

        if self.prudp_version == 0:
            packet = PRUDPPacketV0()
        else:
            packet = PRUDPPacketV1()

        self.emit("Kick", packet)
        client.connected = True
        discriminator = str(client.address)
        if discriminator in self.clients:
            del self.clients[discriminator]

    def on(self, event: str, handler):
        params = list(inspect.signature(handler).parameters.values())
        if len(params) != 1:
            raise ValueError("Handler must take exactly one argument")

        param_type = params[0].annotation

        if param_type == PRUDPPacket or param_type is inspect._empty:
            self.generic_event_handles.setdefault(event, []).append(handler)
        elif param_type == PRUDPPacketV0:
            self.prudp_v0_event_handles.setdefault(event, []).append(handler)
        elif param_type == PRUDPPacketV1:
            self.prudp_v1_event_handles.setdefault(event, []).append(handler)
        else:
            raise ValueError("Handler type not recognized")

    def send_ping(self):
        ping_packet = PRUDPPacket()
        if self.prudp_version == 0:
            ping_packet = PRUDPPacketV0()
        else:
            ping_packet = PRUDPPacketV1()

        ping_packet.source = 0xA1
        ping_packet.destination = 0xAF
        ping_packet.packet_type = PING_PACKET
        ping_packet.flags |= FLAG_NEED_ACK
        ping_packet.flags |= FLAG_RELIABLE

        self.send(ping_packet)

    def send_fragment(self, packet: PRUDPPacket, fragment_id: int):
        data = packet.payload
        packet.fragment_id = fragment_id
        packet.payload = data
        # TODO: Finish this

    def send(self, packet: PRUDPPacket):
        data = packet.payload
        total_len = len(data)
        num_frags = total_len // self.fragment_size

        frag_id = 1
        i = 0
        while i <= num_frags:
            time.sleep(0.5)
            if len(data) < self.fragment_size:
                packet.payload = data
                self.send_fragment(packet, 0)
            else:
                fragment = data[:self.fragment_size]
                packet.payload = fragment
                self.send_fragment(packet, frag_id)
                data = data[self.fragment_size:]
                frag_id += 1
            i += 1