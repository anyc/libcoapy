
from .llapi import *

contexts = []
local_unix_socket_counter = 0
verbosity = 0

COAP_MCAST_ADDR4	= "224.0.1.187"
COAP_MCAST_ADDR4_6	= "0:0:0:0:0:ffff:e000:01bb"
COAP_MCAST_ADDR6_LL	= "ff02::fd" # link-local
COAP_MCAST_ADDR6_SL	= "ff05::fd" # site-local
COAP_MCAST_ADDR6_VS	= "ff0x::fd" # variable-scope
COAP_MCAST_ADDR6	= COAP_MCAST_ADDR6_SL
COAP_DEF_PORT		= 5683
COAPS_DEF_PORT		= 5684

def set_verbosity(verbosity_arg):
	global verbosity
	verbosity = verbosity_arg

def method2code(method):
	if method == "POST":
		return coap_pdu_code_t.COAP_REQUEST_CODE_POST
	elif method == "PUT":
		return coap_pdu_code_t.COAP_REQUEST_CODE_PUT
	elif method == "DELETE":
		return coap_pdu_code_t.COAP_REQUEST_CODE_DELETE
	elif method == "FETCH":
		return coap_pdu_code_t.COAP_REQUEST_CODE_FETCH
	elif method == "PATCH":
		return coap_pdu_code_t.COAP_REQUEST_CODE_PATCH
	elif method == "IPATCH":
		return coap_pdu_code_t.COAP_REQUEST_CODE_IPATCH

def get_string_by_buffer_update(func, default_size):
	buffer = (default_size*ct.c_char)()
	while True:
		string = func(buffer, len(buffer))
		if len(string)+1<len(buffer):
			return string.decode()
		buffer = ((len(buffer)+default_size)*ct.c_char)()

def addr2str(addr):
	s_len = 128
	s_ptr_t = ct.c_char*s_len
	s_ptr = s_ptr_t()
	new_len = coap_print_addr(addr, s_ptr, s_len)
	
	return ct.string_at(s_ptr, new_len).decode()

def ip2str(addr):
	s_len = 128
	s_ptr_t = ct.c_char*s_len
	s_ptr = s_ptr_t()
	coap_print_ip_addr(addr, s_ptr, s_len)
	
	return ct.cast(s_ptr, ct.c_char_p).value.decode()

def getarg(args, kwargs, idx, name, default=None):
	if len(args) >= idx:
		return args[idx]
	elif name in kwargs:
		return kwargs[name]
	else:
		return default

class UnresolvableAddress(Exception):
	def __init__(self, uri, context=None):
		self.uri = uri
		self.ctx = context

class CoapUnexpectedError(Exception):
	pass

def CoapPackageVersion():
	return coap_package_version().decode()

def CoapStringTlsSupport():
	return get_string_by_buffer_update(coap_string_tls_support, 128)

def CoapStringTlsVersion():
	return get_string_by_buffer_update(coap_string_tls_version, 128)

def allocateToken():
	token = coap_binary_t()
	token.length = 8
	
	token_t = ct.c_ubyte * token.length
	token.s = token_t()
	
	return token

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

class CoapPDU():
	"""! PDU base class (see also \ref pdu of libcoap)
	
	A PDU represents a packet in the CoAP protocol.
	"""
	def __init__(self, pdu=None, session=None):
		self.lcoap_pdu = pdu
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
		self.session = session
		self._token = None
		self._pdu_type = None
	
	def getPayload(self):
		"""! get the transmitted payload of a PDU """
		self.size = ct.c_size_t()
		self.payload_ptr = ct.POINTER(ct.c_uint8)()
		self.offset = ct.c_size_t()
		self.total = ct.c_size_t()
		
		try:
			coap_get_data_large(self.lcoap_pdu, ct.byref(self.size), ct.byref(self.payload_ptr), ct.byref(self.offset), ct.byref(self.total))
		except OSError as e:
			if e.errno == 0:
				# libcoap considers no data a failure
				return
			else:
				raise
	
	@property
	def uri(self):
		return str(coap_get_uri_path(self.lcoap_pdu).contents)
	
	@property
	def code(self):
		return coap_pdu_code_t(coap_pdu_get_code(self.lcoap_pdu))
	
	@code.setter
	def code(self, value):
		coap_pdu_set_code(self.lcoap_pdu, value)
	
	def make_persistent(self):
		"""! duplicate the PDU data to ensure it will be available during the
		lifetime of the Python object
		"""
		if not hasattr(self, "payload_copy"):
			if not self.payload_ptr:
				self.getPayload()
			self.payload_copy = ct.string_at(self.payload_ptr, self.size.value)
		
		self._pdu_type = self.type
		
		self._orig_pdu = self.lcoap_pdu
		
		self.lcoap_pdu = coap_pdu_duplicate(
			self.lcoap_pdu,
			self.session.lcoap_session,
			self.lcoap_token.length,
			self.lcoap_token.s,
			None)
	
	@property
	def payload(self):
		"""! public function to get the PDU payload """
		if hasattr(self, "payload_copy"):
			return self.payload_copy
		
		if not self.payload_ptr:
			self.getPayload()
		return ct.string_at(self.payload_ptr, self.size.value)
	
	@payload.setter
	def payload(self, value):
		"""! public function to add a payload to a PDU """
		self.addPayload(value)
	
	def release_payload_cb(self, lcoap_session, payload):
		self.ct_payload = None
		self.session.ctx.pdu_cache.remove(self)
	
	def cancelObservation(self):
		"""! cancel the observation that was established with this PDU """
		coap_cancel_observe(self.session.lcoap_session, self.lcoap_token, self.type)
		if self.token in self.session.token_handlers:
			self.session.token_handlers[self.token]["observe"] = False
	
	@property
	def lcoap_token(self):
		if not self._token:
			self._token = coap_pdu_get_token(self.lcoap_pdu)
		return self._token
	
	@property
	def token_bytes(self):
		return ct.string_at(self.lcoap_token.s, self.lcoap_token.length)
	
	@property
	def token(self):
		"""! get the PDU token as integer """
		return int.from_bytes(self.token_bytes, byteorder=sys.byteorder)
	
	def newToken(self):
		"""! create and add a new token to the PDU """
		self._token = allocateToken()
		
		coap_session_new_token(self.session.lcoap_session, ct.byref(self._token.ctype("length")), self._token.s)
		coap_add_token(self.lcoap_pdu, self._token.length, self._token.s)
	
	@property
	def type(self):
		"""! get the PDU type """
		if self._pdu_type:
			return self._pdu_type
		return coap_pdu_get_type(self.lcoap_pdu)
	
	def getOptions(self, lookup_names=False):
		from . import llapi
		
		opt_iter = coap_opt_iterator_t()
		coap_option_iterator_init(self.lcoap_pdu, ct.byref(opt_iter), COAP_OPT_ALL)
		
		opt_types = {
			COAP_OPTION_URI_PATH: str,
			COAP_OPTION_URI_HOST: str,
			COAP_OPTION_LOCATION_PATH: str,
			COAP_OPTION_URI_QUERY: str,
			COAP_OPTION_LOCATION_QUERY: str,
			COAP_OPTION_PROXY_URI: str,
			COAP_OPTION_PROXY_SCHEME: str,
			COAP_OPTION_RTAG: bytes,
			}
		
		opts = {}
		while True:
			option = coap_option_next(ct.byref(opt_iter), llapi_check=False)
			if not option:
				break
			
			if opt_iter.number in opt_types:
				typ = opt_types[opt_iter.number]
				
				if typ == str:
					value = ct.string_at(coap_opt_value(option), coap_opt_length(option))
				elif typ == bytes:
					value = bytes(ct.cast(coap_opt_value(option), ct.POINTER(ct.c_char * coap_opt_length(option))))
			elif opt_iter.number == COAP_OPTION_CONTENT_FORMAT:
				value = coap_decode_var_bytes(coap_opt_value(option), coap_opt_length(option))
				if lookup_names:
					for key in dir(llapi):
						if key.startswith("COAP_MEDIATYPE_"):
							if getattr(llapi, key, False) == value:
								value = key[len("COAP_MEDIATYPE_"):].lower()
								break
			else:
				if coap_opt_length(option) <= 4:
					value = coap_decode_var_bytes(coap_opt_value(option), coap_opt_length(option))
				elif coap_opt_length(option) <= 8:
					value = coap_decode_var_bytes8(coap_opt_value(option), coap_opt_length(option))
				else:
					value = bytes(ct.cast(coap_opt_value(option), ct.POINTER(ct.c_char * coap_opt_length(option))))
			
			if lookup_names:
				for key in dir(llapi):
					if key.startswith("COAP_OPTION_"):
						if getattr(llapi, key, False) == opt_iter.number:
							if key[len("COAP_OPTION_"):].lower() not in opts:
								opts[key[len("COAP_OPTION_"):].lower().replace("_","-")] = []
							opts[key[len("COAP_OPTION_"):].lower().replace("_","-")].append(value)
			else:
				opts[opt_iter.number] = value
		
		return opts

class CoapPDURequest(CoapPDU):
	"""! PDU that represents a request  """
	
	def addPayload(self, payload):
		"""! add payload to a request PDU """
		if not hasattr(self, "release_payload_cb_ct"):
			self.release_payload_cb_ct = coap_release_large_data_t(self.release_payload_cb)
		
		if isinstance(payload, str):
			self.payload_copy = payload.encode()
		else:
			self.payload_copy = payload
		
		payload_t = ct.c_ubyte * len(self.payload_copy)
		self.ct_payload = payload_t.from_buffer_copy(self.payload_copy)
		
		# make sure our PDU object is not freed before the release_payload_cb is called
		# NOTE: check if really needed
		self.session.ctx.pdu_cache.append(self)
		
		coap_add_data_large_request(
			self.session.lcoap_session,
			self.lcoap_pdu,
			len(payload),
			self.ct_payload,
			self.release_payload_cb_ct,
			self.ct_payload
			)

class CoapPDUResponse(CoapPDU):
	"""! PDU that represents a response """
		
	def addPayload(self, payload, query=None, media_type=0, maxage=-1, etag=0):
		"""! add payload to a response PDU """
		if not hasattr(self, "release_payload_cb_ct"):
			self.release_payload_cb_ct = coap_release_large_data_t(self.release_payload_cb)
		
		if isinstance(payload, str):
			self.payload_copy = payload.encode()
		else:
			self.payload_copy = payload
		
		payload_t = ct.c_ubyte * len(self.payload_copy)
		self.ct_payload = payload_t.from_buffer_copy(self.payload_copy)
		
		self.session.ctx.pdu_cache.append(self)
		
		coap_add_data_large_response(
			self.rs.lcoap_rs,
			self.session.lcoap_session,
			self.request_pdu.lcoap_pdu,
			self.lcoap_pdu,
			query, # coap_string_t
			media_type, # c_uint16
			maxage, # c_int
			etag, # c_uint64
			len(self.payload_copy),
			self.ct_payload,
			self.release_payload_cb_ct,
			self.ct_payload
			)
	
	def is_error(self):
		return (((self.code >> 5) & 0xff) != 0)

class CoapResource():
	"""! a server-side CoAP resource """
	def __init__(self, ctx, uri, observable=True, lcoap_rs=None):
		self.ctx = ctx
		self.handlers = {}
		
		self.ct_handler = coap_method_handler_t(self._handler)
		
		if lcoap_rs:
			self.lcoap_rs = lcoap_rs
		else:
			# keep URI stored
			self.uri_bytes = uri.encode()
			ruri = coap_make_str_const(self.uri_bytes)
			self.lcoap_rs = coap_resource_init(ruri, 0)
		
		coap_resource_set_userdata(self.lcoap_rs, self)
		
		if observable:
			coap_resource_set_get_observable(self.lcoap_rs, 1)
	
	@property
	def uri(self):
		uri_path = coap_resource_get_uri_path(self.lcoap_rs)
		
		return str(uri_path.contents)
	
	def _handler(self, lcoap_resource, lcoap_session, lcoap_request, lcoap_query, lcoap_response):
		session = coap_session_get_app_data(lcoap_session)
		
		req_pdu = CoapPDURequest(lcoap_request, session)
		req_pdu.rs = self
		resp_pdu = CoapPDUResponse(lcoap_response, session)
		resp_pdu.rs = self
		resp_pdu.request_pdu = req_pdu
		
		if session is None:
			session = lcoap_session
		
		self.handlers[req_pdu.code](self, session, req_pdu, lcoap_query.contents if lcoap_query else None, resp_pdu)
		
		if resp_pdu.code == coap_pdu_code_t.COAP_EMPTY_CODE:
			resp_pdu.code = coap_pdu_code_t.COAP_RESPONSE_CODE_CONTENT
	
	def addHandler(self, handler, code=coap_request_t.COAP_REQUEST_GET):
		self.handlers[code] = handler
		
		coap_register_handler(self.lcoap_rs, code, self.ct_handler)

class CoapUnknownResource(CoapResource):
	"""! the unknown resource receives all requests that do not match any previously registered resource """
	def __init__(self, ctx, put_handler, observable=True, handle_wellknown_core=False, flags=0):
		self.ct_handler = coap_method_handler_t(self._handler)
		
		lcoap_rs = coap_resource_unknown_init2(self.ct_handler, flags)
		
		super().__init__(ctx, None, observable=observable, lcoap_rs=lcoap_rs)
		
		if handle_wellknown_core:
			flags |= COAP_RESOURCE_HANDLE_WELLKNOWN_CORE
		
		self.addHandler(put_handler, coap_request_t.COAP_REQUEST_PUT)

class CoapSession():
	"""! represents a CoAP session or connection between two peers (see also \ref session of libcoap)"""
	def __init__(self, ctx, lcoap_session=None):
		self.ctx = ctx
		self.lcoap_session = lcoap_session
		
		self.token_handlers = {}
	
	def release(self):
		if self.lcoap_session!=None:
			coap_session_release(self.lcoap_session)
			self.lcoap_session = None
	
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
	
	def __del__(self):
		if getattr(self, "addr_info", None):
			coap_free_address_info(self.addr_info)
		if getattr(self, "local_addr_unix_path", None):
			if os.path.exists(self.local_addr_unix_path):
				os.unlink(self.local_addr_unix_path);
		self.release()
	
	def sendMessage(self,
				path=None,
				payload=None,
				pdu_type=coap_pdu_type_t.COAP_MESSAGE_CON,
				code=coap_pdu_code_t.COAP_REQUEST_CODE_GET,
				observe=False,
				query=None,
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

class CoapObserver():
	"""! This class is used to handle asynchronous requests. Besides requests with
	observe flag set, this class also handles non-observe requests as the same
	mechanisms are used in both cases.
	"""
	def __init__(self, tx_pdu=None, multiplier=None):
		from asyncio import Event
		
		self.tx_pdu = tx_pdu
		self.ev = Event()
		self.rx_msgs = []
		self._stop = False
		# if stays false, this observer is used to return only a single response
		self.observing = False
		self.multiplier = multiplier
	
	def __del__(self):
		self.stop()
	
	async def wait(self):
		"""! wait on the next response """
		if self.multiplier:
			await self.multiplier.process()
		
		# BUG for some reason, wait() returns True sometimes although is_set() immediately afterwards returns false
		while not self.ev.is_set():
			a = await self.ev.wait()
	
	def addResponse(self, rx_msg):
		if self._stop:
			return
		
		if not self.multiplier:
			rx_msg.make_persistent()
			
			if rx_msg.is_error():
				self.observing = False
		
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
		"""! stop observation """
		if self._stop:
			return
		
		if not self.multiplier:
			if self.observing:
				self.tx_pdu.cancelObservation()
		else:
			self.multiplier.removeSub(self)
		
		self._stop = True
		self.ev.set()

class CoapObserverMultiplier():
	"""! This class enables multiple clients to asynchronously wait on a single subscribed
	resource.
	"""
	def __init__(self, main_observer):
		self.main_observer = main_observer
		self.sub_observers = []
		self.waiting = False
		self.last_pdu = None
	
	def getSubObserver(self):
		self.sub_observers.append( CoapObserver(multiplier=self) )
		
		# A regular observer would return the current value immediately. Here,
		# we simulate this behavior using the last, previously received PDU.
		if self.last_pdu:
			self.sub_observers[-1].addResponse(self.last_pdu)
		
		return self.sub_observers[-1]
	
	def removeSub(self, sub):
		self.sub_observers.remove(sub)
	
	async def process(self):
		if self.waiting:
			return
		self.waiting = True
		
		rx_pdu = await anext(self.main_observer)
		self.last_pdu = rx_pdu
		
		for ob in self.sub_observers:
			ob.addResponse(rx_pdu)
		
		self.waiting = False

class CoapEndpoint():
	"""! basically represents a socket """
	def __init__(self, ctx, uri):
		self.ctx = ctx
		
		self.uri = ctx.parse_uri(uri)
		self.addr_info = ctx.get_addr_info(self.uri)
		
		self.lcoap_endpoint = coap_new_endpoint(self.ctx.lcoap_ctx, self.addr_info.contents.addr, self.addr_info.contents.proto)

class CoapContext():
	"""! a context is the main object for CoAP operations (see also \ref context of libcoap)"""
	def __init__(self):
		contexts.append(self)
		
		self.lcoap_ctx = coap_new_context(None);
		
		self.sessions = []
		self.resources = []
		self._loop = None
		self.pdu_cache = []
		self.coap_fd = -1
		
		self.resp_handler_obj = coap_response_handler_t(self.responseHandler)
		coap_register_response_handler(context=self.lcoap_ctx, handler=self.resp_handler_obj)
		
		self.event_handler_obj = coap_event_handler_t(self.eventHandler)
		coap_register_event_handler(self.lcoap_ctx, self.event_handler_obj)
		
		self.nack_handler_obj = coap_nack_handler_t(self.nackHandler)
		coap_register_nack_handler(self.lcoap_ctx, self.nack_handler_obj)
		
		self.setBlockMode(COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY)
	
	def eventHandler(self, ll_session, event_type):
		event_type = coap_event_t(event_type)
		session = coap_session_get_app_data(ll_session)
		
		if event_type == coap_event_t.COAP_EVENT_SERVER_SESSION_NEW:
			session = CoapSession(self, ll_session)
			
			coap_session_set_app_data(ll_session, session)
			
			self.sessions.append(session)
		elif event_type == coap_event_t.COAP_EVENT_SERVER_SESSION_DEL:
			coap_session_set_app_data(ll_session, 0)
			if session:
				self.sessions.remove(session)
		
		if hasattr(self, "event_callback"):
			ret = self.event_callback(self, session, event_type)
			if ret is None:
				return 0
			else:
				return ret
		else:
			return 0
	
	def nackHandler(self, ll_session, pdu, nack_type, mid):
		nack_type = coap_nack_reason_t(nack_type)
		session = coap_session_get_app_data(ll_session)
		
		if hasattr(self, "nack_callback"):
			self.nack_callback(self, session, pdu, nack_type, mid)
	
	def __del__(self):
		contexts.remove(self)
		if not contexts:
			coap_cleanup()
	
	def setBlockMode(self, mode):
		"""! to choose how much libcoap will help while receiving large data """
		coap_context_set_block_mode(self.lcoap_ctx, mode)
	
	def newSession(self, *args, **kwargs):
		session = CoapClientSession(self, *args, **kwargs)
		
		return session
	
	def addSession(self, session):
		self.sessions.append(session)
	
	def parse_uri(self, uri_str):
		uri = coap_uri_t()
		
		if isinstance(uri_str, str):
			uri.bytes = uri_str.encode()
		else:
			uri.bytes = uri_str
		
		coap_split_uri(ct.cast(ct.c_char_p(uri.bytes), ct.POINTER(ct.c_uint8)), len(uri.bytes), ct.byref(uri))
		
		return uri
	
	def get_addr_info(self, uri, ai_hint_flags=None):
		import socket
		
		if ai_hint_flags is None:
			ai_hint_flags = 0
		
		try:
			addr_info = coap_resolve_address_info(ct.byref(uri.host), uri.port, uri.port, uri.port, uri.port,
				ai_hint_flags, 1 << uri.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
		except NullPointer as e:
			raise UnresolvableAddress(uri, context=self)
		
		return addr_info
	
	def addEndpoint(self, uri):
		self.ep = CoapEndpoint(self, uri)
		
		return self.ep
	
	def addResource(self, resource):
		self.resources.append(resource)
		
		coap_add_resource(self.lcoap_ctx, resource.lcoap_rs)
	
	def getResource(self, uri):
		for resource in self.resources:
			if resource.uri == uri:
				return resource
		
		return None
	
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
		session = coap_session_get_app_data(lcoap_session)
		if session:
			return session.responseHandler(pdu_sent, pdu_recv, mid)
		else:
			print("session object not set", lcoap_session, file=sys.stderr)
			return coap_response_t.COAP_RESPONSE_OK
	
	def io_process(self, timeout_ms=COAP_IO_WAIT):
		if timeout_ms < 0 or timeout_ms > COAP_IO_NO_WAIT:
			raise ValueError
		
		res = coap_io_process(self.lcoap_ctx, timeout_ms)
		if res < 0:
			raise CoapUnexpectedError("coap_io_process()")
		return res
	
	def loop(self, timeout_ms=None, io_timeout_ms=100, rx_wait_list=None):
		def all_responses_received(rx_wait_list):
			for token_hdl in rx_wait_list:
				if not token_hdl.get("ready", False):
					return False
			return True
		
		self.loop_stop = False
		if timeout_ms==None:
			while not self.loop_stop:
				self.io_process(io_timeout_ms)
				if rx_wait_list and all_responses_received(rx_wait_list):
					break
		else:
			while not self.loop_stop and timeout_ms > 0:
				timeout_ms -= self.io_process(min(io_timeout_ms, timeout_ms))
				if rx_wait_list and all_responses_received(rx_wait_list):
					break
	
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
		
		try:
			# this only returns a valid fd if the platform supports epoll
			self.coap_fd = coap_context_get_coap_fd(self.lcoap_ctx)
		except OSError as e:
			if verbosity > 1:
				print("coap_context_get_coap_fd failed", e)
			# we use -1 later to determine if we have to use the alternative
			# event handling
			self._loop.create_task(self.fd_timeout_cb(100))
		else:
			self._loop.add_reader(self.coap_fd, self.fd_callback)
		
		return self._loop
	
	async def fd_timeout_cb(self, timeout_ms):
		from asyncio import sleep
		
		await sleep(timeout_ms / 1000)
		
		self.fd_timeout_fut = None
		
		self.fd_callback()
	
	def fd_callback(self):
		if getattr(self, "fd_timeout_fut", False):
			self.fd_timeout_fut.cancel()
		
		try:
			self.io_process(COAP_IO_NO_WAIT)
		except CoapUnexpectedError as e:
			print("coap_io_process", e)
		
		if self.coap_fd >= 0:
			now = coap_tick_t()
			coap_ticks(ct.byref(now))
			
			timeout_ms = coap_io_prepare_epoll(self.lcoap_ctx, now)
		else:
			# get a list of all sockets from libcoap and add them manually to
			# the asyncio event loop
			if not getattr(self, "max_sockets", False):
				# just guessed values
				self.max_sockets = 8 + 2 * len(getattr(self, "interfaces", []))
			while True:
				read_fds_t = coap_fd_t * self.max_sockets
				write_fds_t = coap_fd_t * self.max_sockets
				read_fds = read_fds_t()
				write_fds = write_fds_t()
				have_read_fds = ct.c_uint()
				have_write_fds = ct.c_uint()
				rem_timeout_ms = ct.c_uint()
				
				coap_io_get_fds(self.lcoap_ctx, 
					read_fds, ct.byref(have_read_fds), self.max_sockets,
					write_fds, ct.byref(have_write_fds), self.max_sockets,
					ct.byref(rem_timeout_ms))
				
				timeout_ms = rem_timeout_ms.value
				
				if have_read_fds.value >= self.max_sockets or have_write_fds.value >= self.max_sockets:
					self.max_sockets *= 2
					continue
				
				for i in range(have_read_fds.value):
					self._loop.add_reader(read_fds[i], self.fd_callback)
				for i in range(have_write_fds.value):
					self._loop.add_writer(write_fds[i], self.fd_callback)
				
				if hasattr(self, "old_read_fds"):
					for fd in self.old_read_fds:
						if fd not in read_fds:
							self._loop.remove_reader(fd)
				if hasattr(self, "old_write_fds"):
					for fd in self.old_write_fds:
						if fd not in write_fds:
							self._loop.remove_writer(fd)
				
				self.old_read_fds = read_fds
				self.old_write_fds = write_fds
				
				break
		
		if timeout_ms > 0:
			self.fd_timeout_fut = self._loop.create_task(self.fd_timeout_cb(timeout_ms))
	
	@staticmethod
	def get_available_interfaces():
		import socket
		
		try:
			import ifaddr
			netifaces = None
		except ModuleNotFoundError:
			ifaddr = None
			try:
				import netifaces
			except ModuleNotFoundError:
				netifaces = None
		
		interfaces = {}
		if ifaddr:
			# interfaces = [ a.nice_name for a in ifaddr.get_adapters() ]
			for adapter in ifaddr.get_adapters():
				intf = lambda: None
				intf.name = adapter.nice_name
				intf.index = adapter.index
				intf.adapter = adapter
				
				intf.ips = []
				for ip in adapter.ips:
					if isinstance(ip.ip, str):
						intf.ips.append( (socket.AF_INET, ip.ip) )
					else:
						intf.ips.append( (socket.AF_INET6, ip.ip[0]) )
				
				interfaces[intf.name] = intf
		elif netifaces:
			if_names = netifaces.interfaces()
			
			for if_name in if_names:
				intf = lambda: None
				intf.name = if_name
				intf.adapter = None
				
				try:
					intf.index = socket.if_nametoindex(if_name)
				except:
					intf.index = None
				
				intf.ips = []
				for link in netifaces.ifaddresses(if_name).get(netifaces.AF_INET, []):
					intf.ips.append( (socket.AF_INET, link['addr']) )
				for link in netifaces.ifaddresses(if_name).get(netifaces.AF_INET6, []):
					intf.ips.append( (socket.AF_INET6, link['addr']) )
				
				interfaces[intf.name] = intf
		else:
			import fcntl
			import struct
			
			if_names = [i[1] for i in socket.if_nameindex()]
			
			def get_ip_address(ifname):
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				return socket.inet_ntoa(fcntl.ioctl(
					s.fileno(),
					0x8915,  # SIOCGIFADDR
					struct.pack('256s', ifname[:15].encode())
					)[20:24])
			
			for if_name in if_names:
				intf = lambda: None
				intf.name = if_name
				intf.adapter = None
				
				try:
					intf.index = socket.if_nametoindex(if_name)
				except:
					intf.index = None
				
				try:
					# TODO
					intf.ips = [(None, get_ip_address(intf.name))]
				except OSError as e:
					# [Errno 99] Cannot assign requested address
					# interfaces without IP?
					if e.errno != 99:
						print(intf.name, e)
					continue
				except Exception as e:
					print(intf.name, e)
					continue
				
				interfaces[intf.name] = intf
		
		return interfaces
	
	@staticmethod
	def get_distinct_ip(intf, ip):
		import ipaddress
		
		ipa = ipaddress.ip_address(ip)
		if ipa.is_link_local:
			if not sys.platform.startswith('win') or 'WINEPREFIX' in os.environ:
				result = ip+"%"+intf.name
			else:
				result = ip+"%"+str(intf.index)
		else:
			result = ip
		
		return result
	
	def enable_multicast(self, interfaces=None, mcast_address=None):
		import socket
		
		if interfaces:
			self.interfaces = interfaces
		else:
			self.interfaces = self.get_available_interfaces()
		
		self.multicast_interfaces = []
		for if_name, intf in self.interfaces.items():
			if if_name == "lo":
				continue
			
			if not intf.ips:
				continue
			
			families = [ family for family, ip in intf.ips ]
			
			if mcast_address:
				mcast_addr = mcast_address
			else:
				if socket.AF_INET6 in families:
					mcast_addr = COAP_MCAST_ADDR6_LL
				else:
					mcast_addr = COAP_MCAST_ADDR4
			
			# mcast_addr = self.get_distinct_ip(intf, mcast_addr)
			mcast_addr = mcast_addr+"%"+str(intf.index)
			
			try:
				if verbosity:
					print("enabling multicast on", if_name, "with address", mcast_addr, intf.index if isinstance(intf.index, int) else "")
				self._enable_multicast(mcast_addr, if_name)
			except Exception as e:
				print("enabling multicast on", if_name, "failed:", e)
			
			self.multicast_interfaces.append(intf)
	
	def _enable_multicast(self, multicast_address=COAP_MCAST_ADDR4, interface_name=None):
		coap_join_mcast_group_intf(self.lcoap_ctx, multicast_address, interface_name)

	def setKeepalive(self, interval_s):
		coap_context_set_keepalive(self.lcoap_ctx, interval_s)

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
