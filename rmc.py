class RMCRequest:
    def __init__(self):
        self.protocol = int()
        self.call = int()
        self.method = int()
        self.parameters = bytearray()

    
class RMCResponse:
    def __init__(self):
        self.size = int()
        self.protocol = int()
        self.call = int()
        self.method = int()
        self.data = bytearray()
        self.error_code = int()