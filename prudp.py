import socket
import time
import datetime
import os
import inspect
import threading
import multiprocessing
import logging
import hmac
import hashlib
import struct
from typing import Dict
from common import SYN_PACKET, CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET, PING_PACKET, FLAG_ACK, FLAG_NEED_ACK, FLAG_RELIABLE, FLAG_HAS_SIZE, FLAG_MULTI_ACK
from rmc import RMCRequest

logger = logging.getLogger(__name__)

class PRUDPClient:
    def __init__(self, address: socket.socket, server: 'PRUDPServer'):
        self.address = address
        self.server = server
        self.secure_key = bytearray()
        self.session_id = int()
        self.pid = int()
        self.local_station_url = str()
        self.session_id = int()
        self.session_key = bytearray()
        self.signature_key = bytearray()
        self.signature_base = int()
        self.connected = bool()
        self.server_connection_signature = bytearray()
        self.client_connection_signature = bytearray()


class PRUDPPacket:
    def __init__(self, client: PRUDPClient, data: bytearray):
        self.client = client  
        self.data = data
        self.version = int()
        self.source = int()
        self.destination = int()
        self.packet_type = int()
        self.flags = int()
        self.fragment_id = int()
        self.connection_signature = bytearray()
        self.payload = bytearray()
        self.rmc_request = RMCRequest()


class PRUDPPacketV0(PRUDPPacket):
    def __init__(self, client: PRUDPClient, data: bytearray):
        super().__init__()
        self.client = client
        self.checksum = int()
        self.data = data

    def calculate_checksum(self, data: bytes) -> int:
        signature_base = self.signature_base
        temp = 0
        steps = len(data) // 4
        for i in range(steps):
            offset = i * 4
            temp += struct.unpack_from('<I', data, offset)[0]
        temp &= 0xFFFFFFFF
        temp_bytes = struct.pack('<I', temp)
        checksum = signature_base
        checksum += sum(data[len(data) & ~3:])
        checksum += sum(temp_bytes)

        return checksum & 0xFF

        


class PRUDPPacketV1(PRUDPPacket):
    def __init__(self):
        super().__init__()
        self.magic = bytearray()
        self.substream_id = int()
        self.supported_functions = int()
        self.initial_sequence_id = int()
        self.max_substream_id = int()

    def calculate_signature(packet, header: bytes, connection_signature: bytes, options: bytes, payload: bytes) -> bytes:
        key = packet.signature_key
        signature_base = struct.pack('<I', packet.signature_base)
        mac = hmac.new(key, digestmod=hashlib.md5)
        mac.update(header[4:])
        mac.update(packet.session_key)
        mac.update(signature_base)
        mac.update(connection_signature)
        mac.update(options)
        mac.update(payload)
        return mac.digest()



class PRUDPServer(PRUDPClient):
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clients: Dict[str, PRUDPClient] = {}
        self.generic_event_handles: Dict[str, list] = {}
        self.prudp_v0_event_handles: Dict[str, list] = {}
        self.prudp_v1_event_handles: Dict[str, list] = {}
        self.access_key = str()
        self.prudp_version = 1
        self.nex_version = int()
        self.fragment_size = 1300
        self.kerberos_password = str()
        self.kerberos_size = 32
        self.kerberos_derivation = 0
        self.kerberos_ticket = int()

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

        print(f"[{datetime.datetime.now()}] PRUDP Server listening on {udp_ip}:{udp_port}")
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
            new_client = PRUDPClient(addr, self)
            self.clients[discriminator] = new_client

        client = self.clients[discriminator]

        data = buffer[:length]

        try:
            if self.prudp_version == 0:
                packet = PRUDPPacketV0(client, data)
            else:
                packet = PRUDPPacketV1(client, data)
        except Exception:
            return None

        if (packet.flags & FLAG_ACK) != 0 or (packet.flags & FLAG_MULTI_ACK) != 0:
            return None

        if (packet.flags & FLAG_NEED_ACK) != 0:
            if packet.packet_type != CONNECT_PACKET or (packet.packet_type == CONNECT_PACKET and len(packet.payload) <= 0):
                threading.Thread(target=self.acknowledge_packet, args=(packet, None)).start()

        if packet.packet_type == SYN_PACKET:
            client.connected = True
            self.emit("Syn", packet)
        elif packet.packet_type == CONNECT_PACKET:
            packet.client_connection_signature = packet.connection_signature
            self.emit("Connect", packet)
        elif packet.packet_type == DATA_PACKET:
            self.emit("Data", packet)
        elif packet.packet_type == DISCONNECT_PACKET:
            self.emit("Disconnect", packet)
            self.kick(client)
        elif packet.packet_type == PING_PACKET:
            self.emit("Ping", packet)

        self.emit("Packet", packet)

        return None
    
    def acknowledge_packet(self, packet: PRUDPPacket, payload: bytearray):
        client = packet.client

        ack_packet = PRUDPPacket()

        if self.prudp_version == 0:
            ack_packet = PRUDPPacketV0(client, None)
        else:
            ack_packet = PRUDPPacketV1(client, None)

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
                serv_connection_signature = os.urandom(16)
                ack_packet.server_connection_signature = serv_connection_signature
                ack_packet.supported_functions = packet.supported_functions
                ack_packet.max_substream_id = 0
                ack_packet.connection_signature = serv_connection_signature

            if packet.packet_type == CONNECT_PACKET:
                ack_packet.connection_signature = bytes(16)
                ack_packet.supported_functions = packet.supported_functions
                ack_packet.initial_sequence_id = 10000
                ack_packet.max_substream_id = 0

            if packet.packet_type == DATA_PACKET:
                pass # TODO 
    
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

    def kick(self, client: PRUDPClient):
        if self.prudp_version == 0:
            packet = PRUDPPacketV0(client, None)
        else:
            packet = PRUDPPacketV1(client, None)

        self.emit("Kick", packet)

        client.connected = False

        discriminator = f"{client.address[0]}:{client.address[1]}"
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

    def send_ping(self, client: PRUDPClient):
        ping_packet = PRUDPPacket()

        if self.prudp_version == 0:
            ping_packet = PRUDPPacketV0(client, None)
        else:
            ping_packet = PRUDPPacketV1(client, None)

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
        fragments = total_len // self.fragment_size

        fragment_id = 1
        for _ in range(fragments + 1):
            time.sleep(0.5)
            if len(data) < self.fragment_size:
                packet.payload = data
                self.send_fragment(packet, 0)
            else:
                fragment = data[:self.fragment_size]
                packet.payload = fragment
                self.send_fragment(packet, fragment_id)
                data = data[self.fragment_size:]
                fragment_id += 1