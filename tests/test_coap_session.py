import asyncio
import importlib
import types
import unittest


session_module = importlib.import_module("libcoapy.CoapSession")


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


if __name__ == "__main__":
	unittest.main()
