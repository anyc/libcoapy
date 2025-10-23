#
# This example resembles the minimal libcoap examples from [1] but written in
# Python with the low-level API of libcoapy.
#
# [1] https://github.com/obgm/libcoap-minimal/blob/main/client.cc
#

from libcoapy.llapi import *
import ctypes

coap_startup()

if len(sys.argv) < 2:
	uri_str = b"coap://localhost/.well-known/core"
else:
	uri_str = sys.argv[1].encode()
uri_t = coap_uri_t()

c_uint8_p = ctypes.POINTER(ctypes.c_uint8)

coap_split_uri(ct.cast(ct.c_char_p(uri_str), c_uint8_p), len(uri_str), ct.byref(uri_t))

ctx = coap_new_context(None);

coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

import socket
addr_info = coap_resolve_address_info(ct.byref(uri_t.host), uri_t.port, uri_t.port, uri_t.port, uri_t.port,
	0, 1 << uri_t.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
if not addr_info:
	print("cannot resolve", uri_str)
	sys.exit(1)

dst = addr_info.contents.addr
is_mcast = coap_is_mcast(ct.byref(dst));

session = coap_new_client_session(ctx, None, ct.byref(dst), coap_proto_t.COAP_PROTO_UDP)

have_response = 0
def my_resp_handler(session, pdu_sent, pdu_recv, mid):
	global have_response
	have_response = 1;
	
	code = coap_pdu_get_code(pdu_recv)
	if code != coap_pdu_code_t.COAP_RESPONSE_CODE_CONTENT:
		print("unexpected result", coap_pdu_code_t(code).name)
		return coap_response_t.COAP_RESPONSE_OK;
	
	size = ct.c_size_t()
	databuf = ct.POINTER(ct.c_uint8)()
	offset = ct.c_size_t()
	total = ct.c_size_t()
	if coap_get_data_large(pdu_recv, ct.byref(size), ct.byref(databuf), ct.byref(offset), ct.byref(total)):
		import string
		
		print(size.value, end=" - ")
		for i in range(size.value):
			print("%02x" % databuf[i], end=" ")
		print(" - ", end="")
		for i in range(size.value):
			if chr(databuf[i]) in string.printable:
				print("%c" % databuf[i], end="")
			else:
				print(" ", end="")
		print()
	else:
		print("no data")
	
	return coap_response_t.COAP_RESPONSE_OK

# we need to prevent this obj from being garbage collected or python/ctypes will segfault
handler_obj = coap_response_handler_t(my_resp_handler)
coap_register_response_handler(ctx, handler_obj)

pdu = coap_pdu_init(coap_pdu_type_t.COAP_MESSAGE_CON,
		coap_pdu_code_t.COAP_REQUEST_CODE_GET,
		coap_new_message_id(session),
		coap_session_max_pdu_size(session));

optlist = ct.POINTER(coap_optlist_t)()
scratch_t = ct.c_uint8 * 100
scratch = scratch_t()
coap_uri_into_options(ct.byref(uri_t), ct.byref(dst), ct.byref(optlist), 1, scratch, ct.sizeof(scratch))

coap_add_optlist_pdu(pdu, ct.byref(optlist))

mid = coap_send(session, pdu)
if mid == COAP_INVALID_MID:
	print("coap_send() failed")
	sys.exit(1)

wait_ms = (coap_session_get_default_leisure(session).integer_part + 1) * 1000;
while have_response == 0 or is_mcast:
	res = coap_io_process(ctx, 1000);
	if res >= 0:
		if wait_ms > 0:
			if res >= wait_ms:
				print("timeout\n")
				break;
			else:
				wait_ms -= res

coap_free_address_info(addr_info)

coap_cleanup()
