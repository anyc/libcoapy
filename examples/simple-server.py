
from libcoapy import *

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

ctx.loop()
