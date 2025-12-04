from .llapi import *

def CoapPackageVersion():
	return coap_package_version().decode()

def CoapStringTlsSupport():
	return get_string_by_buffer_update(coap_string_tls_support, 128)

def CoapStringTlsVersion():
	return get_string_by_buffer_update(coap_string_tls_version, 128)

class CoapGetTlsLibraryVersion():
	"""! wrapper class to gather information about the used TLS library """
	def __init__(self):
		self.contents = coap_get_tls_library_version().contents
	
	@property
	def version(self):
		return self.contents.version
	
	@property
	def type(self):
		return coap_tls_library_t(self.contents.type)
	
	@property
	def built_version(self):
		return self.contents.built_version
	
	def as_dict(self):
		return {'version': self.version, 'type': self.type, 'built_version': self.built_version}
	
	def __str__(self):
		return str(self.as_dict())

if __name__ == "__main__":
	if len(sys.argv) < 2:
		uri_str = "coap://localhost/.well-known/core"
	else:
		uri_str = sys.argv[1]
	
	ctx = CoapContext()
	
	# start a new session with a default hint and key
	session = ctx.newSession(uri_str, hint="user", key="password")
	
	# example how to use the callback function instead of static hint and key
	def ih_cb(session, server_hint):
		print("server hint:", server_hint)
		print("New hint: ", end="")
		hint = input()
		print("Key: ", end="")
		key = input()
		return hint, key
	session.validate_ih_call_back = ih_cb
	
	if True:
		import asyncio
		
		try:
			loop = asyncio.get_running_loop()
		except RuntimeError:
			loop = asyncio.new_event_loop()
		
		ctx.setEventLoop(loop)
		
		async def stop_observer(observer, timeout):
			await asyncio.sleep(timeout)
			observer.stop()
		
		async def startup():
			# immediately return the response
			resp = await session.query(observe=False)
			print(resp.payload)
			
			# return a async generator
			observer = await session.query(observe=True)
			
			# stop observing after five seconds
			asyncio.ensure_future(stop_observer(observer, 5))
			
			async for resp in observer:
				print(resp.payload)
			
			loop.stop()
		
		asyncio.ensure_future(startup(), loop=loop)
		
		try:
			loop.run_forever()
		except KeyboardInterrupt:
			loop.stop()
	else:
		def rx_cb(session, tx_msg, rx_msg, mid):
			print(rx_msg.payload)
			if not tx_msg.observe:
				session.ctx.stop_loop()
		
		session.sendMessage(payload="example data", observe=False, response_callback=rx_cb)
		
		ctx.loop()
