# nex
- PRUDP/NEX library written in Python.

## Features
- [ ] PRUDP
- [ ] HPP
- [ ] PacketV0/V1/Lite
- [x] Kerberos
- [x] RMC

## Example
```python
from prudp import PRUDPServer
import asyncio

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
- PretendoNetwork for the example code with PRUDP.
- Kinnay for anynet streams library.