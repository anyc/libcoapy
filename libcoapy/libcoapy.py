
from .llapi import *

contexts = []
local_unix_socket_counter = 0

class UnresolvableAddress(Exception):
	def __init__(self, uri, context=None):
		self.uri = uri
		self.ctx = context

class CoapPDU():
	def __init__(self, pdu=None):
		self.lcoap_pdu = pdu
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
	
	def getPayload(self):
		self.size = ct.c_size_t()
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
		self.offset = ct.c_size_t()
		self.total = ct.c_size_t()
		
		coap_get_data_large(self.lcoap_pdu, ct.byref(self.size), ct.byref(self.payload_ptr), ct.byref(self.offset), ct.byref(self.total))
	
	@property
	def code(self):
		return coap_pdu_get_code(self.lcoap_pdu)
	
	@code.setter
	def code(self, value):
		coap_pdu_set_code(self.lcoap_pdu, value)
	
	def make_persistent(self):
		if not self.payload_ptr:
			self.getPayload()
		self.payload_copy = ct.string_at(self.payload_ptr, self.size.value)
	
	@property
	def payload(self):
		if hasattr(self, "payload_copy"):
			return self.payload_copy
		
		if not self.payload_ptr:
			self.getPayload()
		return ct.string_at(self.payload_ptr, self.size.value)

class CoapResource():
	def __init__(self, ctx, lcoap_rs, observable=True):
		self.ctx = ctx
		self.lcoap_rs = lcoap_rs
		self.handlers = {}
		
		self.ct_handler = coap_method_handler_t(self._handler)
		
		if observable:
			coap_resource_set_get_observable(self.lcoap_rs, 1)
	
	@property
	def uri(self):
		uri_path = coap_resource_get_uri_path(self.lcoap_rs)
		
		return str(uri_path.contents)
	
	def _handler(self, resource, session, request, query, response):
		req_pdu = CoapPDU(request)
		resp_pdu = CoapPDU(response)
		
		session = coap_session_get_app_data(session)
		
		self.handlers[req_pdu.code](self, session, req_pdu, query.contents if query else None, resp_pdu)
	
	def addHandler(self, handler, code=COAP_REQUEST_GET):
		self.handlers[code] = handler
		
		coap_register_handler(self.lcoap_rs, code, self.ct_handler)

class CoapUnknownResource(CoapResource):
	def __init__(self, ctx, put_handler, observable=True, handle_wellknown_core=False, flags=0):
		self.ct_handler = coap_method_handler_t(self._handler)
		
		lcoap_rs = coap_resource_unknown_init2(self.ct_handler, flags)
		
		super().__init__(ctx, lcoap_rs, observable)
		
		if handle_wellknown_core:
			flags |= COAP_RESOURCE_HANDLE_WELLKNOWN_CORE
		
		self.addHandler(put_handler, COAP_REQUEST_PUT)
		
		coap_resource_set_userdata(self.lcoap_rs, self)

class CoapSession():
	def __init__(self, ctx):
		self.ctx = ctx
		
		self.token_handlers = {}

class CoapClientSession(CoapSession):
	def __init__(self, ctx, uri_str, hint=None, key=None, sni=None):
		super().__init__(ctx)
		
		self.uri = self.ctx.parse_uri(uri_str)
		
		self.addr_info = self.ctx.get_addr_info(self.uri)
		self.local_addr = None
		self.dest_addr = self.addr_info.contents.addr
		
		if coap_is_af_unix(self.dest_addr):
			import os
			global local_unix_socket_counter
			
			# the "in" socket must be unique per session
			self.local_addr = coap_address_t()
			coap_address_init(ct.byref(self.local_addr));
			self.local_addr_unix_path = b"/tmp/libcoapy.%d.%d" % (os.getpid(), local_unix_socket_counter)
			local_unix_socket_counter += 1
			
			coap_address_set_unix_domain(ct.byref(self.local_addr), bytes2uint8p(self.local_addr_unix_path), len(self.local_addr_unix_path))
			
			if os.path.exists(self.local_addr_unix_path):
				os.unlink(self.local_addr_unix_path)
		
		if self.uri.scheme == coap_uri_scheme_t.COAP_URI_SCHEME_COAPS:
			self.dtls_psk = coap_dtls_cpsk_t()
			
			self.dtls_psk.version = COAP_DTLS_SPSK_SETUP_VERSION
			
			self.dtls_psk.validate_ih_call_back = coap_dtls_ih_callback_t(self._validate_ih_call_back)
			self.dtls_psk.ih_call_back_arg = self
			self.dtls_psk.client_sni = sni
				
			# register an initial name and PSK that can get replaced by the callbacks above
			if hint is None:
				hint = getattr(self, "psk_hint", None)
			else:
				self.psk_hint = hint
			if key is None:
				key = getattr(self, "psk_key", None)
			else:
				self.psk_key = key
			
			if isinstance(hint, str):
				hint = hint.encode()
			if isinstance(key, str):
				key = key.encode()
			
			self.dtls_psk.psk_info.hint.s = bytes2uint8p(hint)
			self.dtls_psk.psk_info.key.s = bytes2uint8p(key)
			
			self.dtls_psk.psk_info.hint.length = len(hint)
			self.dtls_psk.psk_info.key.length = len(key)
		
			self.lcoap_session = coap_new_client_session_psk2(self.ctx.lcoap_ctx,
				ct.byref(self.local_addr) if self.local_addr else None,
				ct.byref(self.dest_addr),
				coap_uri_scheme_to_proto(self.uri.scheme),
				self.dtls_psk
				)
		else:
			self.lcoap_session = coap_new_client_session(self.ctx.lcoap_ctx,
				ct.byref(self.local_addr) if self.local_addr else None,
				ct.byref(self.dest_addr),
				coap_uri_scheme_to_proto(self.uri.scheme))
	
	@staticmethod
	def _validate_ih_call_back(server_hint, ll_session, self):
		result = coap_dtls_cpsk_info_t()
		
		if hasattr(self, "validate_ih_call_back"):
			hint, key = self.validate_ih_call_back(self, str(server_hint.contents))
		else:
			hint = getattr(self, "psk_hint", "")
			key = getattr(self, "psk_key", "")
		
		if server_hint.contents != hint:
			# print("server sent different hint: \"%s\" (!= \"%s\")" % (server_hint.contents, hint))
			pass
		
		if isinstance(hint, str):
			hint = hint.encode()
		if isinstance(key, str):
			key = key.encode()
		
		result.hint.s = bytes2uint8p(hint)
		result.key.s = bytes2uint8p(key)
		
		result.hint.length = len(hint)
		result.key.length = len(key)
		
		self.dtls_psk.cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(self.dtls_psk.cb_data, ct.c_void_p).value
	
	def __del__(self):
		if getattr(self, "addr_info", None):
			coap_free_address_info(self.addr_info)
		if getattr(self, "local_addr_unix_path", None):
			if os.path.exists(self.local_addr_unix_path):
				os.unlink(self.local_addr_unix_path);
	
	def sendMessage(self,
				 path=None,
				 payload=None,
				 pdu_type=coap_pdu_type_t.COAP_MESSAGE_CON,
				 code=coap_pdu_code_t.COAP_REQUEST_CODE_GET,
				 observe=False,
				 response_callback=None,
				 response_callback_data=None
		):
		pdu = coap_pdu_init(pdu_type, code, coap_new_message_id(self.lcoap_session), coap_session_max_pdu_size(self.lcoap_session));
		hl_pdu = CoapPDU(pdu)
		
		token_t = ct.c_ubyte * 8
		token = token_t()
		token_length = ct.c_size_t()
		
		coap_session_new_token(self.lcoap_session, ct.byref(token_length), token)
		if coap_add_token(pdu, token_length, token) == 0:
			print("coap_add_token() failed\n")
		
		token = int.from_bytes(ct.string_at(token, token_length.value))
		
		optlist = ct.POINTER(coap_optlist_t)()
		if path:
			if path[0] == "/":
				path = path[1:]
			
			path = path.encode()
			
			coap_path_into_optlist(ct.cast(ct.c_char_p(path), c_uint8_p), len(path), COAP_OPTION_URI_PATH, ct.byref(optlist))
		else:
			coap_uri_into_optlist(ct.byref(self.uri), ct.byref(self.dest_addr), ct.byref(optlist), 1)
		
		if observe:
			scratch_t = ct.c_uint8 * 100
			scratch = scratch_t()
			coap_insert_optlist(ct.byref(optlist),
				coap_new_optlist(COAP_OPTION_OBSERVE,
					coap_encode_var_safe(scratch, ct.sizeof(scratch), COAP_OBSERVE_ESTABLISH),
					scratch)
				)
		
		if optlist:
			rv = coap_add_optlist_pdu(pdu, ct.byref(optlist))
			coap_delete_optlist(optlist)
			if rv != 1:
				raise Exception("coap_add_optlist_pdu() failed\n")
	
		if payload:
			if isinstance(payload, str):
				payload = payload.encode()
			payload_t = ct.c_ubyte * len(payload)
			pdu.payload = payload_t.from_buffer_copy(payload)
			coap_add_data_large_request(self.lcoap_session, pdu, len(payload), pdu.payload, ct.cast(None, coap_release_large_data_t), None)
		
		mid = coap_send(self.lcoap_session, pdu)
		if mid == COAP_INVALID_MID:
			raise Exception("COAP_INVALID_MID")
		
		if response_callback:
			if token not in self.token_handlers:
				self.token_handlers[token] = {}
			self.token_handlers[token]["handler"] = response_callback
			if response_callback_data:
				self.token_handlers[token]["handler_data"] = response_callback_data
			self.token_handlers[token]["pdu"] = hl_pdu
			hl_pdu.observe = observe
			if observe:
				self.token_handlers[token]["observed"] = True
		
		return hl_pdu
	
	def async_response_callback(self, session, tx_msg, rx_msg, mid, observer):
		observer.addResponse(rx_msg)
	
	async def query(self, *args, **kwargs):
		observer = CoapObserver()
		
		kwargs["response_callback"] = self.async_response_callback
		kwargs["response_callback_data"] = observer
		
		tx_pdu = self.sendMessage(*args, **kwargs)
		
		if kwargs.get("observe", False):
			return observer
		else:
			return await observer.__anext__()

class CoapObserver():
	def __init__(self):
		from asyncio import Event
		
		self.ev = Event()
		self.rx_msgs = []
		self._stop = False
	
	async def wait(self):
		await self.ev.wait()
	
	def addResponse(self, rx_msg):
		rx_msg.make_persistent()
		
		self.rx_msgs.append(rx_msg)
		
		self.ev.set()
	
	def __aiter__(self):
		return self
	
	async def __anext__(self):
		if len(self.rx_msgs) == 0:
			await self.wait()
		
		if self._stop:
			raise StopAsyncIteration()
		
		rv = self.rx_msgs.pop()
		
		if len(self.rx_msgs) == 0:
			self.ev.clear()
		
		return rv
	
	def stop(self):
		self._stop = True
		self.ev.set()

class CoapEndpoint():
	def __init__(self, ctx, uri):
		self.ctx = ctx
		
		self.uri = ctx.parse_uri(uri)
		self.addr_info = ctx.get_addr_info(self.uri)
		
		self.lcoap_endpoint = coap_new_endpoint(self.ctx.lcoap_ctx, self.addr_info.contents.addr, coap_uri_scheme_to_proto(self.uri.scheme))

class CoapContext():
	def __init__(self):
		if not contexts:
			coap_startup()
		
		contexts.append(self)
		
		self.lcoap_ctx = coap_new_context(None);
		
		self.sessions = []
		self.resources = []
		self._loop = None
		
		self.resp_handler_obj = coap_response_handler_t(self.responseHandler)
		coap_register_response_handler(self.lcoap_ctx, self.resp_handler_obj)
	
	def __del__(self):
		contexts.remove(self)
		if not contexts:
			coap_cleanup()
	
	def newSession(self, *args, **kwargs):
		session = CoapClientSession(self, *args, **kwargs)
		
		self.sessions.append(session)
		
		return session
	
	def parse_uri(self, uri_str):
		uri = coap_uri_t()
		
		if isinstance(uri_str, str):
			uri.bytes = uri_str.encode()
		else:
			uri.bytes = uri_str
		
		coap_split_uri(ct.cast(ct.c_char_p(uri.bytes), c_uint8_p), len(uri.bytes), ct.byref(uri))
		
		return uri
	
	def get_addr_info(self, uri):
		import socket
		try:
			addr_info = coap_resolve_address_info(ct.byref(uri.host), uri.port, uri.port, uri.port, uri.port,
				socket.AF_UNSPEC, 1 << uri.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
		except NullPointer as e:
			raise UnresolvableAddress(uri, context=self)
		
		return addr_info
	
	def addEndpoint(self, uri):
		self.ep = CoapEndpoint(self, uri)
		
		return self.ep
	
	def addResource(self, resource):
		self.resources.append(resource)
		
		coap_add_resource(self.lcoap_ctx, resource.lcoap_rs)
	
	@staticmethod
	def _verify_psk_sni_callback(sni, session, self):
		result = coap_dtls_spsk_info_t()
		
		if hasattr(self, "verify_psk_sni_callback"):
			hint, key = self.verify_psk_sni_callback(self, sni, session)
		else:
			hint = getattr(self, "psk_hint", "")
			key = getattr(self, "psk_key", "")
		
		if isinstance(hint, str):
			hint = hint.encode()
		if isinstance(key, str):
			key = key.encode()
		
		result.hint.s = bytes2uint8p(hint)
		result.key.s = bytes2uint8p(key)
		
		result.hint.length = len(hint)
		result.key.length = len(key)
		
		session.dtls_spsk_sni_cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(session.dtls_spsk_sni_cb_data, ct.c_void_p).value
	
	@staticmethod
	def _verify_id_callback(identity, session, self):
		result = coap_bin_const_t()
		
		if hasattr(self, "verify_id_callback"):
			key = self.verify_id_callback(self, sni, session)
		else:
			key = getattr(self, "psk_key", "")
		
		if isinstance(key, str):
			key = key.encode()
		
		result.s = bytes2uint8p(key)
		
		result.length = len(key)
		
		session.dtls_spsk_id_cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(session.dtls_spsk_id_cb_data, ct.c_void_p).value
	
	def setup_dtls_psk(self, hint=None, key=None):
		self.dtls_spsk = coap_dtls_spsk_t()
		
		self.dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION
		
		self.dtls_spsk.ct_validate_sni_call_back = coap_dtls_psk_sni_callback_t(self._verify_psk_sni_callback)
		self.dtls_spsk.validate_sni_call_back = self.dtls_spsk.ct_validate_sni_call_back
		self.dtls_spsk.sni_call_back_arg = self
		self.dtls_spsk.ct_validate_id_call_back = coap_dtls_id_callback_t(self._verify_id_callback)
		self.dtls_spsk.validate_id_call_back = self.dtls_spsk.ct_validate_id_call_back
		self.dtls_spsk.id_call_back_arg = self
		
		# register an initial name and PSK that can get replaced by the callbacks above
		if hint is None:
			hint = getattr(self, "psk_hint", "")
		else:
			self.psk_hint = hint
		if key is None:
			key = getattr(self, "psk_key", "")
		else:
			self.psk_key = key
		
		if isinstance(hint, str):
			hint = hint.encode()
		if isinstance(key, str):
			key = key.encode()
		
		self.dtls_spsk.psk_info.hint.s = bytes2uint8p(hint)
		self.dtls_spsk.psk_info.key.s = bytes2uint8p(key)
		
		self.dtls_spsk.psk_info.hint.length = len(hint)
		self.dtls_spsk.psk_info.key.length = len(key)
		
		coap_context_set_psk2(self.lcoap_ctx, ct.byref(self.dtls_spsk))
	
	def responseHandler(self, lcoap_session, pdu_sent, pdu_recv, mid):
		rv = None
		
		token = coap_pdu_get_token(pdu_recv)
		token = int.from_bytes(ct.string_at(token.s, token.length))
		
		session = None
		for s in self.sessions:
			if ct.cast(s.lcoap_session, ct.c_void_p).value == ct.cast(lcoap_session, ct.c_void_p).value:
				session = s
				break
		
		if session and token in session.token_handlers:
			tx_pdu = CoapPDU(pdu_sent)
			rx_pdu = CoapPDU(pdu_recv)
			
			orig_tx_pdu = session.token_handlers[token]["pdu"]
			
			if "handler_data" in session.token_handlers[token]:
				rv = session.token_handlers[token]["handler"](session, orig_tx_pdu, rx_pdu, mid, session.token_handlers[token]["handler_data"])
			else:
				rv = session.token_handlers[token]["handler"](session, orig_tx_pdu, rx_pdu, mid)
			if not session.token_handlers[token].get("observed", False):
				del session.token_handlers[token]
		else:
			if not session:
				print("unexpected session", lcoap_session, file=sys.stderr)
		
		if rv is None:
			rv = coap_response_t.COAP_RESPONSE_OK
		
		return rv
	
	def loop(self, timeout=None):
		self.loop_stop = False
		while not self.loop_stop:
			res = coap_io_process(self.lcoap_ctx, 1000);
			if res >= 0:
				if timeout is not None and timeout > 0:
					if res >= timeout:
						break;
					else:
						timeout -= res
			else:
				raise Exception("coap_io_process() returned:", res)
	
	def stop_loop(self):
		if self._loop:
			self._loop.stop()
		else:
			self.loop_stop = True
	
	def setEventLoop(self, loop=None):
		if loop is None:
			from asyncio import get_event_loop
			try:
				self._loop = asyncio.get_running_loop()
			except RuntimeError:
				self._loop = asyncio.new_event_loop()
		else:
			self._loop = loop
		
		self.coap_fd = coap_context_get_coap_fd(self.lcoap_ctx)
		
		self._loop.add_reader(self.coap_fd, self.fd_callback)
	
	async def fd_timeout_cb(self, timeout_ms):
		from asyncio import sleep
		
		await sleep(timeout_ms / 1000)
		
		self.fd_timeout_fut = None
		self.fd_callback()
	
	def fd_callback(self):
		if getattr(self, "fd_timeout_fut", False):
			self.fd_timeout_fut.cancel()
		
		now = coap_tick_t()
		
		coap_io_process(self.lcoap_ctx, COAP_IO_NO_WAIT)
		
		coap_ticks(ct.byref(now))
		timeout_ms = coap_io_prepare_epoll(self.lcoap_ctx, now);
		
		if timeout_ms > 0:
			self.fd_timeout_ms = timeout_ms
			self.fd_timeout_fut = self._loop.create_task(self.fd_timeout_cb(self.fd_timeout_ms))

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
