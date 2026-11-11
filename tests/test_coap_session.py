import asyncio
import importlib
import types
import unittest
from unittest.mock import Mock, patch


session_module = importlib.import_module("libcoapy.CoapSession")
pdu_module = importlib.import_module("libcoapy.CoapPDU")


class FakePDU:
	def __init__(self, token, code):
		self.token = token
		self.code = code
		self.persisted = False

	def make_persistent(self):
		self.persisted = True


class ResponseFactory:
	@classmethod
	def createFrom(cls, pdu, session):
		return pdu


class RequestFactory:
	@classmethod
	def createFrom(cls, pdu, session):
		return pdu


class CoapSessionResponseHandlerTest(unittest.TestCase):
	def setUp(self):
		self.response_class = session_module.CoapPDUResponse
		self.request_class = session_module.CoapPDURequest
		session_module.CoapPDUResponse = ResponseFactory
		session_module.CoapPDURequest = RequestFactory

		self.loop = asyncio.new_event_loop()
		self.session = object.__new__(session_module.CoapSession)
		self.session.ctx = types.SimpleNamespace(_loop=self.loop)
		self.session.token_handlers = {}

	def tearDown(self):
		session_module.CoapPDUResponse = self.response_class
		session_module.CoapPDURequest = self.request_class
		self.loop.close()

	def test_async_callback_receives_final_response_after_handler_removal(self):
		token = 2
		callback_calls = []

		async def callback(session, tx_pdu, rx_pdu, mid, callback_data):
			callback_calls.append((session, tx_pdu, rx_pdu, mid, callback_data))

		original_request = FakePDU(token, None)
		transmitted_request = FakePDU(token, None)
		response = FakePDU(
			token,
			session_module.coap_pdu_code_t.COAP_RESPONSE_CODE_CHANGED,
		)
		self.session.token_handlers[token] = {
			"tx_pdu": original_request,
			"handler": callback,
			"handler_data": "callback data",
		}

		self.session.responseHandler(transmitted_request, response, 2)
		self.loop.run_until_complete(asyncio.sleep(0))

		self.assertNotIn(token, self.session.token_handlers)
		self.assertEqual(
			callback_calls,
			[(self.session, original_request, response, 2, "callback data")],
		)


class CoapSessionQueryTest(unittest.TestCase):
	def test_query_uses_create_request_for_payload_callback(self):
		session = object.__new__(session_module.CoapSession)
		created_requests = []
		response = object()

		class FakeObserver:
			def __init__(self):
				self.observing = False

			async def __anext__(self):
				return response

		class FakeRequest:
			def __init__(self):
				self.send = Mock()
				self.make_persistent = Mock()

		request = FakeRequest()

		def create_request(*args, **kwargs):
			created_requests.append((args, kwargs))
			return request

		session.createRequest = create_request
		original_observer = session_module.CoapObserver
		session_module.CoapObserver = FakeObserver
		try:
			payload_callback = lambda *args: b"chunk"
			result = asyncio.run(session.query(
				path="update",
				payload_callback=payload_callback,
				payload_size=5,
			))
		finally:
			session_module.CoapObserver = original_observer

		self.assertIs(result, response)
		self.assertEqual(len(created_requests), 1)
		self.assertEqual(created_requests[0][0], ())
		self.assertIs(created_requests[0][1]["payload_callback"], payload_callback)
		self.assertEqual(created_requests[0][1]["payload_size"], 5)
		self.assertIsNotNone(created_requests[0][1]["response_callback"])
		request.send.assert_called_once_with()
		request.make_persistent.assert_called_once_with()

	def test_create_request_accepts_zero_length_payload_callback(self):
		session = object.__new__(session_module.CoapSession)
		original_request_class = session_module.CoapPDURequest
		payload_callback = lambda *args: b""

		class FakeRequest:
			def __init__(self, session, pdu_type, code):
				self.payload_callback_args = None

			def setOptions(self, **kwargs):
				pass

			def setTXPayloadCallback(self, *args):
				self.payload_callback_args = args

			def setResponseCallback(self, *args):
				pass

		session_module.CoapPDURequest = FakeRequest
		try:
			request = session.createRequest(
				path="update",
				payload_callback=payload_callback,
				payload_size=0,
			)
		finally:
			session_module.CoapPDURequest = original_request_class

		self.assertIs(request.payload_callback_args[0], payload_callback)
		self.assertEqual(request.payload_callback_args[1], 0)


class CoapPDUStreamingPayloadTest(unittest.TestCase):
	def test_missing_release_callback_registers_null_and_retains_data(self):
		pdu = object.__new__(pdu_module.CoapPDU)
		callback_data = object()
		pdu.session = types.SimpleNamespace(lcoap_session=object())
		pdu.lcoap_pdu = object()
		add_data_calls = []
		with patch.object(
			pdu_module,
			"coap_add_data_large_request_app",
			lambda *args: add_data_calls.append(args) or 1,
			create=True,
		):
			pdu.setTXPayloadCallback(lambda *args: b"", 0, payload_cb_data=callback_data)

		self.assertFalse(add_data_calls[0][3])
		self.assertIs(pdu.payload_callback_data, callback_data)


if __name__ == "__main__":
	unittest.main()
