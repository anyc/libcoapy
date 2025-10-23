
from .llapi import *
from .common import *
from .CoapPDU import *
from .CoapObserver import *

class CoapSession():
	"""! represents a CoAP session or connection between two peers (see also \ref session of libcoap)"""
	def __init__(self, ctx, lcoap_session=None):
		self.ctx = ctx
		self.lcoap_session = lcoap_session
		
		self.token_handlers = {}
		
		weakref.finalize(self, self.release)
	
	def release(self):
		if self.lcoap_session!=None:
			# unset app_data in case lcoap_session is referenced by others
			coap_session_set_app_data(self.lcoap_session, None)
			coap_session_release(self.lcoap_session)
			self.lcoap_session = None
		if self.ctx:
			ctx = self.ctx
			self.ctx = None
			ctx.removeSession(self)
	
	def is_valid(self):
		return not not self.lcoap_session
	
	def getInterfaceIndex(self):
		return coap_session_get_ifindex(self.lcoap_session)
	
	def getInterfaceName(self):
		from socket import if_indextoname
		
		index = self.getInterfaceIndex()
		try:
			import ifaddr
		except ModuleNotFoundError:
			ifaddr = None
			pass
		else:
			for adapter in ifaddr.get_adapters():
				if adapter.index == index:
					return adapter.nice_name
		
		try:
			return if_indextoname(index)
		except OSError as e:
			if ifaddr:
				# TODO addresses could be the same on different interfaces
				for adapter in ifaddr.get_adapters():
					for ip in adapter.ips:
						if isinstance(ip.ip, str):
							if ip.ip == self.local_ip:
								return adapter.nice_name
						else:
							if ip.ip[0] == self.local_ip:
								return adapter.nice_name
			
			print("if_indextoname failed:", e)
			raise
	
	@property
	def remote_address(self):
		return addr2str(coap_session_get_addr_remote(self.lcoap_session))
	
	@property
	def local_address(self):
		return addr2str(coap_session_get_addr_local(self.lcoap_session))
	
	@property
	def remote_ip(self):
		return ip2str(coap_session_get_addr_remote(self.lcoap_session))
	
	@property
	def local_ip(self):
		return ip2str(coap_session_get_addr_local(self.lcoap_session))
	
	async def responseHandler_async(self, pdu_sent, pdu_recv, mid):
		if "handler_data" in handler_dict:
			await self.token_handlers["handler"](self, pdu_sent, pdu_recv, mid, self.token_handlers["handler_data"])
		else:
			await self.token_handlers["handler"](self, pdu_sent, pdu_recv, mid)
	
	def responseHandler(self, pdu_sent, pdu_recv, mid):
		rv = None
		
		rx_pdu = CoapPDUResponse(pdu_recv, self)
		if pdu_sent:
			tx_pdu = CoapPDURequest(pdu_sent, self)
		else:
			tx_pdu = None
		
		token = rx_pdu.token
		
		if token in self.token_handlers:
			orig_tx_pdu = self.token_handlers[token]["tx_pdu"]
			self.token_handlers[token]["ready"] = True
			rx_pdu.request_pdu = orig_tx_pdu
			
			if self.token_handlers[token].get("save_rx_pdu", False):
				rx_pdu.make_persistent()
				self.token_handlers[token]["rx_pdu"] = rx_pdu
			
			if "handler" in self.token_handlers[token]:
				handler = self.token_handlers[token]["handler"]
				
				from inspect import iscoroutinefunction
				if iscoroutinefunction(handler):
					import asyncio
					
					if not self.token_handlers[token].get("observed", False):
						del self.token_handlers[token]
					
					tx_pdu.make_persistent()
					rx_pdu.make_persistent()
					
					asyncio.ensure_future(self.responseHandler_async(orig_tx_pdu, rx_pdu, mid), loop=self.ctx._loop)
				else:
					if "handler_data" in self.token_handlers[token]:
						rv = handler(self, orig_tx_pdu, rx_pdu, mid, self.token_handlers[token]["handler_data"])
					else:
						rv = handler(self, orig_tx_pdu, rx_pdu, mid)
					
					if not self.token_handlers[token].get("observed", False):
						del self.token_handlers[token]
		else:
			if tx_pdu:
				print("txtoken", tx_pdu.token, tx_pdu.token_bytes)
			print("unexpected rxtoken", rx_pdu.token, rx_pdu.token_bytes)
			
			if not tx_pdu and (rx_pdu.type == coap_pdu_type_t.COAP_MESSAGE_CON or rx_pdu.type == coap_pdu_type_t.COAP_MESSAGE_NON):
				return coap_response_t.COAP_RESPONSE_FAIL
		
		return coap_response_t.COAP_RESPONSE_OK if rv is None else rv
	
	
	def sendMessage(self,
			path=None,
			payload=None,
			pdu_type=coap_pdu_type_t.COAP_MESSAGE_CON,
			code=coap_pdu_code_t.COAP_REQUEST_CODE_GET,
			observe=False,
			query=None,
			options=None,
			save_rx_pdu=False,
			response_callback=None,
			response_callback_data=None
		):
		"""! prepare and send a PDU for this session
		
		@param path: the path of the resource
		@param payload: the payload to send with the PDU
		@param pdu_type: request confirmation of the request (CON) or not (NON)
		@param code: the code similar to HTTP (e.g., GET, POST, PUT, ...)
		@param observe: observe/subscribe the resource
		@param query: send a query - comparable to path?arg1=val1&arg2=val2 in HTTP
		@param options: set additional options (e.g., COAP_OPTION_CONTENT_FORMAT) using a list of (option_code, value) tuples
		@param save_rx_pdu: automatically make the response PDU persistent
		@param response_callback: function that will be called if a response is received
		@param response_callback_data: additional data that will be passed to \p response_callback
	
		@return the resulting dictionary in token_handler
		"""
		
		if not self.lcoap_session:
			self.setup_connection()
			if not self.lcoap_session:
				raise Exception("session not set up")
		
		pdu = coap_pdu_init(pdu_type, code, coap_new_message_id(self.lcoap_session), coap_session_max_pdu_size(self.lcoap_session));
		hl_pdu = CoapPDURequest(pdu, self)
		
		hl_pdu.newToken()
		token = hl_pdu.token
		
		optlist = ct.POINTER(coap_optlist_t)()
		if path:
			if path[0] == "/":
				path = path[1:]
			
			if isinstance(path, str):
				path = path.encode()
			
			coap_path_into_optlist(ct.cast(ct.c_char_p(path), ct.POINTER(ct.c_uint8)), len(path), COAP_OPTION_URI_PATH, ct.byref(optlist))
		else:
			coap_uri_into_optlist(ct.byref(self.uri), ct.byref(self.dest_addr), ct.byref(optlist), 1)
		
		hl_pdu.observe = observe
		if observe:
			scratch_t = ct.c_uint8 * 100
			scratch = scratch_t()
			coap_insert_optlist(ct.byref(optlist),
				coap_new_optlist(COAP_OPTION_OBSERVE,
					coap_encode_var_safe(scratch, ct.sizeof(scratch), COAP_OBSERVE_ESTABLISH),
					scratch)
				)
		
		if query:
			if isinstance(query, str):
				query = query.encode()
			
			coap_query_into_optlist(ct.cast(ct.c_char_p(query), ct.POINTER(ct.c_uint8)), len(query), COAP_OPTION_URI_QUERY, ct.byref(optlist))
		
		if options:
			scratch_t = ct.c_uint8 * 8
			scratch = scratch_t()
			for opt_num, value in options:
				coap_insert_optlist(ct.byref(optlist),
					coap_new_optlist(opt_num,
						coap_encode_var_safe(scratch, ct.sizeof(scratch), value),
						scratch)
					)
		
		if optlist:
			rv = coap_add_optlist_pdu(pdu, ct.byref(optlist))
			coap_delete_optlist(optlist)
			if rv != 1:
				raise Exception("coap_add_optlist_pdu() failed\n")
		
		if payload is not None:
			hl_pdu.payload = payload
		
		mid = coap_send(self.lcoap_session, pdu)
		
		self.token_handlers[token] = {}
		self.token_handlers[token]["tx_pdu"] = hl_pdu
		if observe:
			self.token_handlers[token]["observed"] = True
		if save_rx_pdu:
			self.token_handlers[token]["save_rx_pdu"] = True
		if response_callback:
			self.token_handlers[token]["handler"] = response_callback
			if response_callback_data:
				self.token_handlers[token]["handler_data"] = response_callback_data
		
		# libcoap automatically signals an epoll fd that work has to be done, without
		# epoll we have to do this ourselves.
		if self.ctx._loop and self.ctx.coap_fd < 0:
			self.ctx.fd_callback()
		
		return self.token_handlers[token]
	
	def request(self, *args, **kwargs):
		"""! send a synchronous request and return the response
		
		accepts same parameters as \\link libcoapy.libcoapy.CoapClientSession.sendMessage sendMessage() \\endlink
		"""
		lkwargs={}
		for key in ("timeout_ms", "io_timeout_ms"):
			if key in kwargs:
				lkwargs[key] = kwargs.pop(key)
		
		token_hdl = self.sendMessage(*args, **kwargs, save_rx_pdu=True)
		
		self.ctx.loop(**lkwargs, rx_wait_list=[token_hdl])
		
		if token_hdl.get("ready", False):
			return token_hdl["rx_pdu"]
		else:
			raise TimeoutError
	
	def async_response_callback(self, session, tx_msg, rx_msg, mid, observer):
		rx_msg.make_persistent()
		observer.addResponse(rx_msg)
	
	async def query(self, *args, **kwargs):
		r"""! start an asynchronous request and return a generator object if
		observe=True is set, else return the response pdu
		
		accepts same parameters as \link libcoapy.libcoapy.CoapClientSession.sendMessage sendMessage() \endlink
		"""
		observer = CoapObserver()
		
		kwargs["response_callback"] = self.async_response_callback
		kwargs["response_callback_data"] = observer
		
		tx_pdu = self.sendMessage(*args, **kwargs)["tx_pdu"]
		tx_pdu.make_persistent()
		observer.tx_pdu = tx_pdu
		
		if kwargs.get("observe", False):
			observer.observing = True
			return observer
		else:
			return await observer.__anext__()

class CoapClientSession(CoapSession):
	"""! represents a session initiated by a client """
	def __init__(self, ctx, uri=None, hint=None, key=None, sni=None):
		super().__init__(ctx)
		
		ctx.addSession(self)
		
		if uri:
			self.uri_str = uri
			self.uri = self.ctx.parse_uri(uri)
		if hint or key or sni:
			self.setup_connection(hint, key, sni)
	
	def setup_connection(self, hint=None, key=None, sni=None):
		# from socket import AI_ALL, AI_V4MAPPED
		# ai_hint_flags=AI_ALL | AI_V4MAPPED)
		
		if not self.ctx:
			if verbosity > 0:
				print("setup_connection() called but no context set", file=sys.stderr)
			return
		
		self.addr_info = self.ctx.get_addr_info(self.uri)
		self.local_addr = None
		self.dest_addr = self.addr_info.contents.addr
		
		if coap_is_af_unix(self.dest_addr):
			import os
			global local_unix_socket_counter
			
			if False:
				# TODO we cannot use this path for now as it is difficult to calculate
				# the size of coap_address_t which (for now) is just an opaque structure.
				# Maybe it would be best to add a coap_address_alloc() function to libcoap
				# to be portable across different systems.
				
				# the "in" socket must be unique per session
				self.local_addr = coap_address_t()
				coap_address_init(ct.byref(self.local_addr))
				# max length due to sockaddr_in6 buffer size: 26 bytes
				self.local_addr_unix_path = b"/tmp/libcoapy.%d.%d" % (os.getpid(), local_unix_socket_counter)
				local_unix_socket_counter += 1
				
				coap_address_set_unix_domain(ct.byref(self.local_addr), bytes2uint8p(self.local_addr_unix_path), len(self.local_addr_unix_path))
			else:
				# In this path, we use get_addr_info to allocate a coap_address_t for us.
				
				# max length due to sockaddr_in6 buffer size: 26 bytes
				self.local_addr_unix_path = b"coap://%%2ftmp%%2flcoapy%d.%d" % (os.getpid(), local_unix_socket_counter)
				local_unix_socket_counter += 1
				
				self.local_uri = self.ctx.parse_uri(self.local_addr_unix_path)
				self.local_addr_info = self.ctx.get_addr_info(self.local_uri)
				self.local_addr = self.local_addr_info.contents.addr
			
			if os.path.exists(self.local_addr_unix_path):
				os.unlink(self.local_addr_unix_path)
		
		if self.uri.scheme == coap_uri_scheme_t.COAP_URI_SCHEME_COAPS:
			self.dtls_psk = coap_dtls_cpsk_t()
			
			self.dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION
			
			self.dtls_psk.validate_ih_call_back = coap_dtls_ih_callback_t(self._validate_ih_call_back)
			self.dtls_psk.ih_call_back_arg = self
			
			if isinstance(sni, str):
				sni = sni.encode()
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
			
			# we have to set a value or the callback will not be called
			if not hint:
				hint = "unset"
			if not key:
				key = "unset"
			
			if isinstance(hint, str):
				hint = hint.encode()
			if isinstance(key, str):
				key = key.encode()
			
			self.dtls_psk.psk_info.identity.s = bytes2uint8p(hint)
			self.dtls_psk.psk_info.key.s = bytes2uint8p(key)
			
			self.dtls_psk.psk_info.identity.length = len(hint) if hint else 0
			self.dtls_psk.psk_info.key.length = len(key) if key else 0
		
			self.lcoap_session = coap_new_client_session_psk2(self.ctx.lcoap_ctx,
				ct.byref(self.local_addr) if self.local_addr else None,
				ct.byref(self.dest_addr),
				self.addr_info.contents.proto,
				self.dtls_psk
				)
			coap_session_set_app_data(self.lcoap_session, self)
		else:
			self.lcoap_session = coap_new_client_session(self.ctx.lcoap_ctx,
				ct.byref(self.local_addr) if self.local_addr else None,
				ct.byref(self.dest_addr),
				self.addr_info.contents.proto)
			coap_session_set_app_data(self.lcoap_session, self)
	
	@staticmethod
	def _validate_ih_call_back(server_hint, ll_session, self):
		result = coap_dtls_cpsk_info_t()
		
		if hasattr(self, "validate_ih_call_back"):
			hint, key = self.validate_ih_call_back(self, str(server_hint.contents).encode())
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
		
		result.identity.s = bytes2uint8p(hint)
		result.key.s = bytes2uint8p(key)
		
		result.identity.length = len(hint)
		result.key.length = len(key)
		
		self.dtls_psk.cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(self.dtls_psk.cb_data, ct.c_void_p).value
	
	def release(self):
		super().release()
		
		if getattr(self, "addr_info", None):
			coap_free_address_info(self.addr_info)
			del self.addr_info
		if getattr(self, "local_addr_unix_path", None):
			if os.path.exists(self.local_addr_unix_path):
				os.unlink(self.local_addr_unix_path);
			del self.local_addr_unix_path
