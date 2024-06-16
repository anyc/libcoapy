
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
