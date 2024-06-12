
from .llapi import *

contexts = []

class UnresolvableAddress(Exception):
	def __init__(self, uri, context=None):
		self.uri = uri
		self.ctx = context

class CoapMessage():
	def __init__(self, pdu=None):
		self.pdu = pdu
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
	
	def getPayload(self):
		self.size = ct.c_size_t()
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
		self.offset = ct.c_size_t()
		self.total = ct.c_size_t()
		
		coap_get_data_large(self.pdu, ct.byref(self.size), ct.byref(self.payload_ptr), ct.byref(self.offset), ct.byref(self.total))
	
	@property
	def bytes(self):
		if not self.payload_ptr:
			self.getPayload()
		return ct.string_at(self.payload_ptr, self.size.value)

class CoapClientSession():
	def __init__(self, ctx, uri_str):
		self.ctx = ctx
		
		self.uri = self.parse_uri(uri_str)
		
		import socket
		self.addr_info = coap_resolve_address_info(ct.byref(self.uri.host), self.uri.port, self.uri.port, self.uri.port, self.uri.port,
			socket.AF_UNSPEC, 1 << self.uri.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
		if not self.addr_info:
			raise UnresolvableAddress(self.uri, context=self)
		
		self.dest_addr = self.addr_info.contents.addr
		
		self.lcoap_session = coap_new_client_session(self.ctx.lcoap_ctx, None, ct.byref(self.dest_addr), 1<<self.uri.scheme)
		if not self.lcoap_session:
			raise OSError(-1, "coap_new_client_session failed")
	
	def __del__(self):
		coap_free_address_info(self.addr_info)
	
	def parse_uri(self, uri_str):
		uri = coap_uri_t()
		
		if isinstance(uri_str, str):
			uri.bytes = uri_str.encode()
		else:
			uri.bytes = uri_str
		
		coap_split_uri(ct.cast(ct.c_char_p(uri.bytes), c_uint8_p), len(uri.bytes), ct.byref(uri))
		
		return uri
	
	def sendMessage(self, path=None, payload=None, pdu_type=COAP_MESSAGE_CON, code=coap_pdu_code_t.COAP_REQUEST_CODE_GET, response_callback=None):
		pdu = coap_pdu_init(pdu_type, code, coap_new_message_id(self.lcoap_session), coap_session_max_pdu_size(self.lcoap_session));
		
		if path:
			if path[0] == "/":
				path = path[1:]
			
			# TODO how much extra space?
			buf_t = ct.c_char * (len(path) + 1)
			buf = buf_t()
			optlist = ct.POINTER(coap_optlist_t)()
			buflen = ct.c_size_t()
			
			buflen.value = len(buf)
			bufit = ct.cast(buf, ct.c_voidp)
			
			n_elements = coap_split_path(path, len(path), buf, ct.byref(buflen))
			while n_elements > 0:
				coap_insert_optlist(ct.byref(optlist),
									coap_new_optlist(COAP_OPTION_URI_PATH,
													coap_opt_length(ct.cast(bufit, ct.POINTER(ct.c_ubyte))),
													coap_opt_value(ct.cast(bufit, ct.POINTER(ct.c_ubyte)))
													)
									)
				
				bufit.value += coap_opt_size(ct.cast(bufit, ct.POINTER(ct.c_ubyte)));
				
				n_elements -= 1
			
			if optlist:
				rv = coap_add_optlist_pdu(pdu, ct.byref(optlist))
				coap_delete_optlist(optlist)
				if rv != 1:
					raise Exception("coap_add_optlist_pdu() failed\n")
		else:
			optlist = ct.POINTER(coap_optlist_t)()
			scratch_t = ct.c_uint8 * 100
			scratch = scratch_t()
			
			coap_uri_into_options(ct.byref(self.uri), ct.byref(self.dest_addr), ct.byref(optlist), 1, scratch, ct.sizeof(scratch))
			
			coap_add_optlist_pdu(pdu, ct.byref(optlist))
			coap_delete_optlist(optlist)
		
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
			mid = coap_pdu_get_mid(pdu)
			self.ctx.mid_handlers[mid] = response_callback
		
		return CoapMessage(pdu)
	

class CoapContext():
	def __init__(self):
		if not contexts:
			coap_startup()
		
		contexts.append(self)
		
		self.lcoap_ctx = coap_new_context(None);
		
		self.sessions = []
		
		self.resp_handler_obj = coap_response_handler_t(self.responseHandler)
		coap_register_response_handler(self.lcoap_ctx, self.resp_handler_obj)
		
		self.mid_handlers = {}
	
	def __del__(self):
		contexts.remove(self)
		if not contexts:
			coap_cleanup()
	
	def newSession(self, uri_str):
		session = CoapClientSession(self, uri_str)
		
		self.sessions.append(session)
		
		return session
	
	def responseHandler(self, lcoap_session, pdu_sent, pdu_recv, mid):
		rv = None
		
		if mid in self.mid_handlers:
			session = None
			for s in self.sessions:
				if ct.cast(s.lcoap_session, ct.c_void_p).value == ct.cast(lcoap_session, ct.c_void_p).value:
					session = s
					break
			if not session:
				raise Exception("unexpected session", lcoap_session)
			
			tx_msg = CoapMessage(pdu_sent)
			rx_msg = CoapMessage(pdu_recv)
			
			rv = self.mid_handlers[mid](session, tx_msg, rx_msg, mid)
			del self.mid_handlers[mid]
		
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
		self.loop_stop = True

if __name__ == "__main__":
	if len(sys.argv) < 2:
		uri_str = "coap://localhost/.well-known/core"
	else:
		uri_str = sys.argv[1]
	
	ctx = CoapContext()
	
	session = ctx.newSession(uri_str)
	
	def rx_cb(session, tx_msg, rx_msg, mid):
		print(rx_msg.bytes)
		session.ctx.stop_loop()
	
	session.sendMessage(None, response_callback=rx_cb)
	
	ctx.loop()
