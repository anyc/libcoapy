libcoapy
========

libcoapy project enables communication over the CoAP protocol (RFC 7252). The
`llapi` module provides ctypes-based wrappers for the [libcoap](https://libcoap.net/)
C library. The `libcoapy` module uses `llapi` to provide a high-level class interface
to the libcoap functions.

Dependencies:
-------------

 - libcoap

Example
-------

```python
from libcoapy import *

ctx = CoapContext()

session = ctx.newSession("coap://localhost")

def rx_cb(session, tx_msg, rx_msg, mid):
	print(rx_msg.bytes)
	session.ctx.stop_loop()

session.sendMessage(path=".well-known/core", response_callback=rx_cb)

ctx.loop()
```

For an example with the low-level API, see `examples/ll-client.py`.
