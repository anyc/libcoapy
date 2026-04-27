
from libcoapy import *
import threading

# callback that is called for unexpected resources
def handler_unknown_uri(resource, session, request, query, response):
	print("received unexpected request:", request.code, request.uri)
	
	response.code = coap_pdu_code_t.COAP_RESPONSE_CODE_NOT_FOUND

def echo_handler(resource, session, request, query, response):
	response.payload = request.payload

def time_handler(resource, session, request, query, response):
	import datetime
	now = datetime.datetime.now()
	response.payload = str(now)

def asyncResponse_ready(coap_async):
	# trigger calling of asyncResponse_handler() again
	coap_async.trigger()

def asyncResponse_handler(resource, session, request, query, response):
	# are we called a second time for this request?
	if session.findAsyncResponse(request):
		# return the response now
		response.payload = "delayed result"
		return
	
	# If we come here, this is the first time we handle this request.
	
	# tell libcoap that we do not have the response right now
	coap_async = CoapAsync(session, request)
	
	# do something to get the response
	t = threading.Timer(2, asyncResponse_ready, args=(coap_async,))
	t.start()

coap_set_log_level(coap_log_t.COAP_LOG_INFO)

ctx = CoapContext()

# listen on localhost (IPv4 & v6)
ctx.addEndpoint("coap://[::1]")

# register a special resource that will be called for unexpected paths
unknown_rs = CoapUnknownResource(ctx, handler_unknown_uri)
unknown_rs.addHandler(handler_unknown_uri)
ctx.addResource(unknown_rs)

# resource with path "/time"
time_rs = CoapResource(ctx, "time")
time_rs.addHandler(time_handler)
ctx.addResource(time_rs)

# resource with path "/echo"
echo_rs = CoapResource(ctx, "echo")
echo_rs.addHandler(echo_handler)
ctx.addResource(echo_rs)

# resource with path "/asyncResponse"
asyncResponse_rs = CoapResource(ctx, "asyncResponse")
asyncResponse_rs.addHandler(asyncResponse_handler)
ctx.addResource(asyncResponse_rs)

class myCoapAsync(CoapAsync):
	def startProcessing(self, resource, session, request_pdu, query):
		# do something to get the response
		t = threading.Timer(2, self.asyncResponse_ready)
		t.start()
	
	def asyncResponse_ready(self):
		self.response_payload = "delayed result"
		# notify libcoap(y) that the result is ready
		self.trigger()

# resource with path "/asyncResponse2"
asyncResponse_rs = CoapResource(ctx, "asyncResponse2")
asyncResponse_rs.addHandler(myCoapAsync.asyncResponse_handler)
ctx.addResource(asyncResponse_rs)

ctx.loop()
