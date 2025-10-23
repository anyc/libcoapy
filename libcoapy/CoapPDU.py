
from .llapi import *
from .common import *

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
		if self.session and self.session.ctx:
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
