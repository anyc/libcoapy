
from .llapi import *
from .common import *
from .CoapPDU import *

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
