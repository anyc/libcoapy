
from libcoapy import *

if len(sys.argv) < 2:
	uri_str = "coap://localhost"
else:
	uri_str = sys.argv[1]

ctx = CoapContext()

session = ctx.newSession(uri_str)

#
# First, we make a synchronous request which returns the response directly.
#

rx_pdu = session.request(path=".well-known/core")
print(rx_pdu.payload)

#
# Second, we start an asynchronous request and the response gets passed to a
# callback function.
#

def rx_cb(session, tx_msg, rx_msg, mid):
	print(rx_msg.getOptions(lookup_names=True))
	print(tx_msg.getOptions(lookup_names=True))
	print(rx_msg.payload)
	session.ctx.stop_loop()

session.sendMessage(path=".well-known/core", response_callback=rx_cb)

#
# For an asynchronous request with asyncio, see the async-subscribs.py example.
#

ctx.loop()
