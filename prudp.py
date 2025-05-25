import socket
import threading

class PRUDPClient:
    pass


class PRUDPPacket:
    def __init__(self):
        self.payload = bytearray()


class PRUDPServer:
    def __init__(self):
        self.socket = None
        self.running = False
        self.prudp_version = 1
        self.nex_version = int()
        self.access_key = str()
        self.fragment_size = 1300

    def create(self, addr: str, port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((addr, port))
        self.running = True
        print(f"[+] PRUDPServer listening on {addr}:{port}")

        def server_loop():
            while self.running:
                try:
                    data, client_addr = self.socket.recvfrom(4096)
                    print(f"[*] Received from {client_addr}: {data}")
                except OSError:
                    break

        thread = threading.Thread(target=server_loop, daemon=True)
        thread.start()

        input("[!] Press ENTER to stop the server...\n")

        self.running = False
        self.socket.close()
        print("[x] PRUDPServer closed.")