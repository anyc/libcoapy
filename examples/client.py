
from libcoapy import *

ctx = CoapContext()

session = ctx.newSession("coap://localhost/.well-known/core")

def rx_cb(session, tx_msg, rx_msg, mid):
	print(rx_msg.bytes)
	session.ctx.stop_loop()

session.sendMessage(None, response_callback=rx_cb)

ctx.loop()
