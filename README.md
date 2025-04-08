libcoapy
========

libcoapy project enables communication over the CoAP protocol (RFC 7252). The
`llapi` module provides ctypes-based wrappers for the [libcoap](https://libcoap.net/)
C library. The `libcoapy` module uses `llapi` to provide a high-level class interface
to the libcoap functions.

Dependencies:
-------------

 - [libcoap](https://libcoap.net/) (v4.3.5 or higher is recommended)
 - [ifaddr](https://pypi.org/project/ifaddr/) (optional, to query all IPs of an interface)
 - [netifaces](https://pypi.org/project/netifaces/) (optional alternative to ifaddr)

Status
------

The llapi module provides a complete interface for the current version of the libcoap
library. The high-level API of libcoapy is still missing some parts and might change
in the future.

Portability
-----------

libcoapy is a pure python module and the underlying libcoap supports several platforms
like Linux, Windows, MacOS and Android. However, libcoap (and hence libcoapy) does not
support all features on all platforms and with all possible SSL/TLS libraries.

If you want to use libcoapy with asyncio on platforms without epoll, like Windows,
it might be necessary to choose an event loop that supports `add_reader()`. On
Windows you might need to add this to your code before initializing the loop:

```
if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
	asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

Provided tools
--------------

In the examples folder, this repo provides the following general-purpose tools:

* coap-gui - a small Tkinter-based GUI to interact with a CoAP server
* coarl - a CLI tool that provides a similar interface as [curl](https://curl.se/)

Documentation
-------------

API documentation: https://anyc.github.io/libcoapy/

Example: client
---------------

```python
from libcoapy import *

if len(sys.argv) < 2:
	uri_str = "coap://localhost"
else:
	uri_str = sys.argv[1]

ctx = CoapContext()

session = ctx.newSession(uri_str)

def rx_cb(session, tx_msg, rx_msg, mid):
	print(rx_msg.payload)
	session.ctx.stop_loop()

session.sendMessage(path=".well-known/core", response_callback=rx_cb)

ctx.loop()
```

Example: server
---------------

```python
from libcoapy import *

def echo_handler(resource, session, request, query, response):
	response.payload = request.payload

def time_handler(resource, session, request, query, response):
	import datetime
	now = datetime.datetime.now()
	response.payload = str(now)

ctx = CoapContext()
ctx.addEndpoint("coap://[::]")

time_rs = CoapResource(ctx, "time")
time_rs.addHandler(time_handler)
ctx.addResource(time_rs)

echo_rs = CoapResource(ctx, "echo")
echo_rs.addHandler(echo_handler)
ctx.addResource(echo_rs)

ctx.loop()
```

More examples can be found in the `examples` directory.
