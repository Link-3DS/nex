# nex
- PRUDP/NEX library written in Python.

## Features
- [ ] PRUDP
- [ ] HPP
- [ ] PacketV0/V1/Lite
- [x] Kerberos
- [x] RMC
- [x] Errors

## Example
```python
import asyncio
from prudp import PRUDPServer

async def main():
    prudp = PRUDPServer()
    prudp.prudp_version = 1
    prudp.kerberos_size = 16
    prudp.access_key = "ridfebb9"
    prudp.on("Data", lambda event: print("Received data event:", event))
    await prudp.listen("0.0.0.0:6000")


asyncio.run(main())
```

## Credits
- PretendoNetwork for the architecture of the PRUDP rewritten in Python (I must later change it to put my own implementation).
- Kinnay for anynet streams library.