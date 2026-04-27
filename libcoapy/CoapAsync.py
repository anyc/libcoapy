
from .llapi import *
from .common import *

class CoapAsync():
	"""! CoAP responses can be delayed without causing a re-request after a timeout by the client. This
	class can be used to control such a delayed response.
	"""
	def __init__(self, session, request_pdu, timeout_ticks=0):
		self.session = session
		self.request_pdu = request_pdu
		
		self.lcoap_async = coap_register_async(self.session.lcoap_session, request_pdu.lcoap_pdu, timeout_ticks)
		
		self._app_data_free_cb = coap_cache_app_data_free_callback_t(self.app_data_release)
		coap_async_set_app_data2(self.lcoap_async, self, self._app_data_free_cb)
		
		# make sure we are not garbage collected until libcoap does not need us anymore
		self.session.pyobj_cache.append(self)
	
	def release(self):
		coap_free_async(self.session.lcoap_session, self.lcoap_async)
	
	def trigger(self):
		"""! called to notify libcoap(y) that the result is ready """
		coap_async_trigger(self.lcoap_async)
	
	def set_delay(self, delay):
		"""! change the delay until the response will be requested again """
		coap_async_set_delay(self.lcoap_async, delay)
	
	@staticmethod
	def app_data_release(self):
		self.session.pyobj_cache.remove(self)
	
	def startProcessing(self, resource, session, request_pdu, query):
		"""! overrideable method that should initiate the retrieval of the response data """
		pass
	
	def getResponse(self, response_pdu):
		"""! overrideable method that should setup the response PDU """
		
		# convenience function to setup the response
		if getattr(self, "response_payload", None):
			response_pdu.payload = self.response_payload
			return coap_pdu_code_t.COAP_RESPONSE_CODE_CONTENT
	
	@classmethod
	def asyncResponse_handler(cls, resource, session, request_pdu, query, response_pdu):
		"""! callback function that can be passed to CoapResource.addHandler() """
		
		# are we called a second time for this request?
		self = session.findAsyncResponse(request_pdu)
		if self:
			return self.getResponse(response_pdu)
		
		# If we come here, this is the first time we handle this request.
		
		# tell libcoap that we do not have the response right now
		self = cls(session, request_pdu)
		
		self.startProcessing(resource, session, request_pdu, query)
