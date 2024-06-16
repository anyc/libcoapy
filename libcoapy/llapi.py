
import os, sys, enum
import ctypes as ct

verbosity = 0

class NullPointer(Exception):
	pass

class ctypes_enum_gen(enum.IntEnum):
	@classmethod
	def from_param(cls, param):
		return ct.c_int(param)

coap_log_t = ctypes_enum_gen("coap_log_t", [
	"COAP_LOG_EMERG",
	"COAP_LOG_ALERT",
	"COAP_LOG_CRIT",
	"COAP_LOG_ERR",
	"COAP_LOG_WARN",
	"COAP_LOG_NOTICE",
	"COAP_LOG_INFO",
	"COAP_LOG_DEBUG",
	"COAP_LOG_OSCORE",
	"COAP_LOG_DTLS_BASE",
	], start=0)

coap_proto_t = ctypes_enum_gen("coap_proto_t", [
		"COAP_PROTO_NONE",
		"COAP_PROTO_UDP",
		"COAP_PROTO_DTLS",
		"COAP_PROTO_TCP",
		"COAP_PROTO_TLS",
		"COAP_PROTO_WS",
		"COAP_PROTO_WSS",
		"COAP_PROTO_LAST"
		], start=0)

coap_resolve_type_t = ctypes_enum_gen("coap_resolve_type_t", [
		"COAP_RESOLVE_TYPE_LOCAL",
		"COAP_RESOLVE_TYPE_REMOTE"
		], start=0)

coap_uri_scheme_t = ctypes_enum_gen("coap_uri_scheme_t", [
		"COAP_URI_SCHEME_COAP",
		"COAP_URI_SCHEME_COAPS",
		"COAP_URI_SCHEME_COAP_TCP",
		"COAP_URI_SCHEME_COAPS_TCP",
		"COAP_URI_SCHEME_HTTP",
		"COAP_URI_SCHEME_HTTPS",
		"COAP_URI_SCHEME_COAP_WS",
		"COAP_URI_SCHEME_COAPS_WS",
		"COAP_URI_SCHEME_LAST",
		], start=0)

coap_response_t = ctypes_enum_gen("coap_response_t", [
		"COAP_RESPONSE_FAIL",
		"COAP_RESPONSE_OK",
		], start=0)

def COAP_SIGNALING_CODE(N): return ((int((N)/100) << 5) | (N)%100)

class coap_pdu_signaling_proto_t(ctypes_enum_gen):
	COAP_SIGNALING_CSM     = COAP_SIGNALING_CODE(701)
	COAP_SIGNALING_PING    = COAP_SIGNALING_CODE(702)
	COAP_SIGNALING_PONG    = COAP_SIGNALING_CODE(703)
	COAP_SIGNALING_RELEASE = COAP_SIGNALING_CODE(704)
	COAP_SIGNALING_ABORT   = COAP_SIGNALING_CODE(705)

COAP_BLOCK_USE_LIBCOAP = 0x01
COAP_BLOCK_SINGLE_BODY = 0x02

COAP_OBSERVE_ESTABLISH = 0
COAP_OBSERVE_CANCEL    = 1

COAP_MESSAGE_CON = 0
COAP_MESSAGE_NON = 1
COAP_MESSAGE_ACK = 2
COAP_MESSAGE_RST = 3

COAP_REQUEST_GET     = 1
COAP_REQUEST_POST    = 2
COAP_REQUEST_PUT     = 3
COAP_REQUEST_DELETE  = 4
COAP_REQUEST_FETCH   = 5
COAP_REQUEST_PATCH   = 6
COAP_REQUEST_IPATCH  = 7

COAP_OPTION_IF_MATCH       =  1
COAP_OPTION_URI_HOST       =  3
COAP_OPTION_ETAG           =  4
COAP_OPTION_IF_NONE_MATCH  =  5
COAP_OPTION_OBSERVE        =  6
COAP_OPTION_URI_PORT       =  7
COAP_OPTION_LOCATION_PATH  =  8
COAP_OPTION_URI_PATH       = 11
COAP_OPTION_CONTENT_FORMAT = 12
COAP_OPTION_CONTENT_TYPE   = COAP_OPTION_CONTENT_FORMAT
COAP_OPTION_MAXAGE         = 14
COAP_OPTION_URI_QUERY      = 15
COAP_OPTION_ACCEPT         = 17
COAP_OPTION_LOCATION_QUERY = 20
COAP_OPTION_PROXY_URI      = 35
COAP_OPTION_PROXY_SCHEME   = 39
COAP_OPTION_SIZE1          = 60

def COAP_RESPONSE_CODE(N): return (( int((N)/100) << 5) | (N)%100)

class coap_pdu_code_t(ctypes_enum_gen):
	COAP_EMTPY_CODE = 0
	
	COAP_REQUEST_CODE_GET    = COAP_REQUEST_GET
	COAP_REQUEST_CODE_POST   = COAP_REQUEST_POST
	COAP_REQUEST_CODE_PUT    = COAP_REQUEST_PUT
	COAP_REQUEST_CODE_DELETE = COAP_REQUEST_DELETE
	COAP_REQUEST_CODE_FETCH  = COAP_REQUEST_FETCH
	COAP_REQUEST_CODE_PATCH  = COAP_REQUEST_PATCH
	COAP_REQUEST_CODE_IPATCH = COAP_REQUEST_IPATCH
	
	COAP_RESPONSE_CODE_CREATED                    = COAP_RESPONSE_CODE(201)
	COAP_RESPONSE_CODE_DELETED                    = COAP_RESPONSE_CODE(202)
	COAP_RESPONSE_CODE_VALID                      = COAP_RESPONSE_CODE(203)
	COAP_RESPONSE_CODE_CHANGED                    = COAP_RESPONSE_CODE(204)
	COAP_RESPONSE_CODE_CONTENT                    = COAP_RESPONSE_CODE(205)
	COAP_RESPONSE_CODE_CONTINUE                   = COAP_RESPONSE_CODE(231)
	COAP_RESPONSE_CODE_BAD_REQUEST                = COAP_RESPONSE_CODE(400)
	COAP_RESPONSE_CODE_UNAUTHORIZED               = COAP_RESPONSE_CODE(401)
	COAP_RESPONSE_CODE_BAD_OPTION                 = COAP_RESPONSE_CODE(402)
	COAP_RESPONSE_CODE_FORBIDDEN                  = COAP_RESPONSE_CODE(403)
	COAP_RESPONSE_CODE_NOT_FOUND                  = COAP_RESPONSE_CODE(404)
	COAP_RESPONSE_CODE_NOT_ALLOWED                = COAP_RESPONSE_CODE(405)
	COAP_RESPONSE_CODE_NOT_ACCEPTABLE             = COAP_RESPONSE_CODE(406)
	COAP_RESPONSE_CODE_INCOMPLETE                 = COAP_RESPONSE_CODE(408)
	COAP_RESPONSE_CODE_CONFLICT                   = COAP_RESPONSE_CODE(409)
	COAP_RESPONSE_CODE_PRECONDITION_FAILED        = COAP_RESPONSE_CODE(412)
	COAP_RESPONSE_CODE_REQUEST_TOO_LARGE          = COAP_RESPONSE_CODE(413)
	COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT = COAP_RESPONSE_CODE(415)
	COAP_RESPONSE_CODE_UNPROCESSABLE              = COAP_RESPONSE_CODE(422)
	COAP_RESPONSE_CODE_TOO_MANY_REQUESTS          = COAP_RESPONSE_CODE(429)
	COAP_RESPONSE_CODE_INTERNAL_ERROR             = COAP_RESPONSE_CODE(500)
	COAP_RESPONSE_CODE_NOT_IMPLEMENTED            = COAP_RESPONSE_CODE(501)
	COAP_RESPONSE_CODE_BAD_GATEWAY                = COAP_RESPONSE_CODE(502)
	COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE        = COAP_RESPONSE_CODE(503)
	COAP_RESPONSE_CODE_GATEWAY_TIMEOUT            = COAP_RESPONSE_CODE(504)
	COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED     = COAP_RESPONSE_CODE(505)
	COAP_RESPONSE_CODE_HOP_LIMIT_REACHED          = COAP_RESPONSE_CODE(508)

	COAP_SIGNALING_CODE_CSM                       = coap_pdu_signaling_proto_t.COAP_SIGNALING_CSM
	COAP_SIGNALING_CODE_PING                      = coap_pdu_signaling_proto_t.COAP_SIGNALING_PING
	COAP_SIGNALING_CODE_PONG                      = coap_pdu_signaling_proto_t.COAP_SIGNALING_PONG
	COAP_SIGNALING_CODE_RELEASE                   = coap_pdu_signaling_proto_t.COAP_SIGNALING_RELEASE
	COAP_SIGNALING_CODE_ABORT                     = coap_pdu_signaling_proto_t.COAP_SIGNALING_ABORT

coap_tid_t = ct.c_int
coap_mid_t = ct.c_int
coap_opt_t = ct.c_uint8

COAP_INVALID_MID = -1
COAP_INVALID_TID = COAP_INVALID_MID

class LStructure(ct.Structure):
	def __str__(self):
		return "<{}: {{{}}}>".format(
			self.__class__.__name__,
			", ".join(["{}: {}".format(
					f[0],
					str(getattr(self, f[0]))
				)
				for f in self._fields_])
			)

class coap_address_t(ct.Structure):
	pass

class coap_context_t(ct.Structure):
	pass

class coap_optlist_t(ct.Structure):
	pass

class coap_pdu_t(ct.Structure):
	pass

class coap_resource_t(ct.Structure):
	pass

class coap_session_t(ct.Structure):
	pass

# looks like ctypes does not support coap_response_t (enum) as return value
coap_response_handler_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.POINTER(coap_pdu_t), coap_mid_t)
coap_release_large_data_t = ct.CFUNCTYPE(None, ct.POINTER(coap_session_t), ct.c_void_p)

def c_uint8_p_to_str(uint8p, length):
	b = ct.string_at(uint8p, length)
	try:
		return b.decode()
	except:
		return b

c_uint8_p = ct.POINTER(ct.c_uint8)

class coap_addr_info_t(ct.Structure):
	pass
coap_addr_info_t._fields_ = [
		("next", ct.POINTER(coap_addr_info_t)),
		("scheme", ct.c_int),
		("proto", ct.c_int),
		("addr", coap_address_t),
		]

class coap_fixed_point_t(LStructure):
	_fields_ = [("integer_part", ct.c_uint16), ("fractional_part", ct.c_uint16)]


class coap_string_t(LStructure):
	_fields_ = [("length", ct.c_size_t), ("s", c_uint8_p)]
	
	def __str__(self):
		return str(c_uint8_p_to_str(self.s, self.length))

class coap_str_const_t(LStructure):
	_fields_ = [("length", ct.c_size_t), ("s", c_uint8_p)]
	
	def __str__(self):
		return str(c_uint8_p_to_str(self.s, self.length))

coap_bin_const_t = coap_str_const_t

class coap_uri_t(LStructure):
	_fields_ = [
			("host", coap_str_const_t),
			("port", ct.c_uint16),
			("path", coap_str_const_t),
			("query", coap_str_const_t),
			("scheme", ct.c_int),
			]

class coap_dtls_spsk_info_t(LStructure):
	_fields_ = [
		("hint", coap_bin_const_t),
		("key", coap_bin_const_t),
		]

# actually returns coap_dtls_spsk_info_t
coap_dtls_psk_sni_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.c_char_p, ct.POINTER(coap_session_t), ct.py_object)
# actually returns coap_bin_const_t
coap_dtls_id_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_bin_const_t), ct.POINTER(coap_session_t), ct.py_object)

COAP_DTLS_SPSK_SETUP_VERSION = 1

class coap_dtls_spsk_t(LStructure):
	_fields_ = [
		("version", ct.c_uint8),
		("reserved", ct.c_uint8 * 7),
		("validate_id_call_back", coap_dtls_id_callback_t),
		("id_call_back_arg", ct.py_object),
		("validate_sni_call_back", coap_dtls_psk_sni_callback_t),
		("sni_call_back_arg", ct.py_object),
		("psk_info", coap_dtls_spsk_info_t),
		]

class coap_dtls_cpsk_info_t(LStructure):
	_fields_ = [
		("hint", coap_bin_const_t),
		("key", coap_bin_const_t),
		]

# actually returns coap_dtls_cpsk_info_t
coap_dtls_ih_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_str_const_t), ct.POINTER(coap_session_t), ct.py_object)

class coap_dtls_cpsk_t(LStructure):
	_fields_ = [
		("version", ct.c_uint8),
		("reserved", ct.c_uint8 * 7),
		("validate_ih_call_back", coap_dtls_ih_callback_t),
		("ih_call_back_arg", ct.py_object),
		("client_sni", ct.c_char_p),
		("psk_info", coap_dtls_cpsk_info_t),
		]

def bytes2uint8p(b, cast=c_uint8_p):
	return ct.cast(ct.create_string_buffer(b), cast)

library_functions = [
	{ "name": "coap_startup", "restype": None },
	{ "name": "coap_cleanup", "restype": None },
	{ "name": "coap_set_log_level", "args": [coap_log_t], "restype": None },
	{ "name": "coap_split_uri", "args": [ct.POINTER(ct.c_uint8), ct.c_size_t, ct.POINTER(coap_uri_t)] },
	{ "name": "coap_split_path", "args": [ct.c_char_p, ct.c_size_t, ct.c_char_p, ct.POINTER(ct.c_size_t)] },
	{ "name": "coap_new_context", "args": [ct.POINTER(coap_address_t)], "restype": ct.POINTER(coap_context_t) },
	{ "name": "coap_new_client_session", "args": [ct.POINTER(coap_context_t), ct.POINTER(coap_address_t), ct.POINTER(coap_address_t), coap_proto_t], "restype": ct.POINTER(coap_session_t) },
	{ "name": "coap_resolve_address_info", "args": [
			ct.POINTER(coap_str_const_t),
			ct.c_uint16,
			ct.c_uint16,
			ct.c_uint16,
			ct.c_uint16,
			ct.c_int,
			ct.c_int,
			coap_resolve_type_t,
			],
		"restype": ct.POINTER(coap_addr_info_t)
		},
	{ "name": "coap_is_bcast", "args": [ct.POINTER(coap_address_t)] },
	{ "name": "coap_is_mcast", "args": [ct.POINTER(coap_address_t)] },
	{ "name": "coap_is_af_unix", "args": [ct.POINTER(coap_address_t)] },
	{ "name": "coap_free_address_info", "args": [ct.POINTER(coap_addr_info_t)], "restype": None },
	{ "name": "coap_register_response_handler", "args": [ct.POINTER(coap_context_t), coap_response_handler_t], "restype": None },
	{ "name": "coap_pdu_init", "args": [ct.c_uint8, ct.c_uint8, ct.c_uint16, ct.c_size_t], "restype": ct.POINTER(coap_pdu_t) },
	{ "name": "coap_new_message_id", "args": [ct.POINTER(coap_session_t)], "restype": ct.c_uint16 },
	{ "name": "coap_session_max_pdu_size", "args": [ct.POINTER(coap_session_t)], "restype": ct.c_size_t },
	{ "name": "coap_uri_into_options", "args": [
			ct.POINTER(coap_uri_t),
			ct.POINTER(coap_address_t),
			ct.POINTER(ct.POINTER(coap_optlist_t)),
			ct.c_int,
			ct.POINTER(ct.c_uint8),
			ct.c_size_t,
			]},
	{ "name": "coap_add_optlist_pdu", "args": [ct.POINTER(coap_pdu_t), ct.POINTER(ct.POINTER(coap_optlist_t))], "expect": 1 },
	{ "name": "coap_send", "args": [ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t)], "restype": coap_mid_t },
	{ "name": "coap_session_get_default_leisure", "args": [ct.POINTER(coap_session_t)], "restype": coap_fixed_point_t },
	{ "name": "coap_io_process", "args": [ct.POINTER(coap_context_t), ct.c_uint32] },
	
	{ "name": "coap_context_set_block_mode", "args": [ct.POINTER(coap_context_t), ct.c_uint8], "restype": None },
	{ "name": "coap_add_data_large_request", "args": [
			ct.POINTER(coap_session_t),
			ct.POINTER(coap_pdu_t),
			ct.c_size_t,
			ct.POINTER(ct.c_uint8),
			coap_release_large_data_t,
			ct.py_object,
			]},
	{ "name": "coap_add_data_large_response", "args": [
			ct.POINTER(coap_resource_t),
			ct.POINTER(coap_session_t),
			ct.POINTER(coap_pdu_t),
			ct.POINTER(coap_pdu_t),
			ct.POINTER(coap_string_t),
			ct.c_uint16,
			ct.c_int,
			ct.c_uint64,
			ct.c_size_t,
			ct.POINTER(ct.c_uint8),
			coap_release_large_data_t,
			ct.py_object,
			]},
	{ "name": "coap_get_data_large", "args": {
		"pdu": ct.POINTER(coap_pdu_t),
		"length": ct.POINTER(ct.c_size_t),
		"_data": ct.POINTER(ct.POINTER(ct.c_uint8)),
		"offset": ct.POINTER(ct.c_size_t),
		"total": ct.POINTER(ct.c_size_t),
		}, "expect": 1},
	
	{ "name": "coap_pdu_get_code", "args": [ct.POINTER(coap_pdu_t)], "restype": coap_pdu_code_t},
	{ "name": "coap_pdu_get_mid", "args": [ct.POINTER(coap_pdu_t)], "restype": coap_mid_t},
	{ "name": "coap_pdu_get_token", "args": [ct.POINTER(coap_pdu_t)], "restype": coap_bin_const_t},
	
	{ "name": "coap_new_optlist", "args": [ct.c_uint16, ct.c_size_t, ct.POINTER(ct.c_uint8)], "restype": ct.POINTER(coap_optlist_t) },
	{ "name": "coap_add_option", "args": [ct.POINTER(coap_pdu_t), ct.c_uint16, ct.c_size_t, ct.c_uint8], "restype": ct.c_size_t, "res_error": 0 },
	{ "name": "coap_insert_optlist", "args": [ct.POINTER(ct.POINTER(coap_optlist_t)), ct.POINTER(coap_optlist_t)], "expect": 1 },
	{ "name": "coap_delete_optlist", "args": [ct.POINTER(coap_optlist_t)], "restype": None },
	{ "name": "coap_opt_length", "args": [ct.POINTER(coap_opt_t)], "restype": ct.c_uint32 },
	{ "name": "coap_opt_value", "args": [ct.POINTER(coap_opt_t)], "restype": ct.POINTER(ct.c_uint8) },
	{ "name": "coap_opt_size", "args": [ct.POINTER(coap_opt_t)], "restype": ct.c_size_t },
	{ "name": "coap_encode_var_safe", "args": [ct.POINTER(ct.c_uint8), ct.c_size_t, ct.c_uint], "restype": ct.c_uint, "res_error": 0},
	
	{ "name": "coap_session_new_token", "args": [ct.POINTER(coap_session_t), ct.POINTER(ct.c_size_t), ct.POINTER(ct.c_uint8)], "restype": None },
	{ "name": "coap_add_token", "args": [ct.POINTER(coap_pdu_t), ct.c_size_t, ct.POINTER(ct.c_uint8)], "res_error": 0 },
	
	{ "name": "coap_address_init", "args": [ct.POINTER(coap_address_t)], "restype": None },
	{ "name": "coap_address_set_unix_domain", "args": [ct.POINTER(coap_address_t), ct.POINTER(ct.c_uint8), ct.c_size_t], "expect": 1 },
	
	{ "name": "coap_context_set_psk2", "args": [ct.POINTER(coap_context_t), ct.POINTER(coap_dtls_spsk_t)] },
	{ "name": "coap_new_client_session_psk2", "args": {
		"context": ct.POINTER(coap_context_t),
		"local_if": ct.POINTER(coap_address_t),
		"server": ct.POINTER(coap_address_t),
		"proto": coap_proto_t,
		"setup_data": ct.POINTER(coap_dtls_cpsk_t),
		},
		"restype": ct.POINTER(coap_session_t) },
	]

libcoap = ct.CDLL('libcoap-3-openssl.so.3')
libc = ct.CDLL('libc.so.6')
libc.free.args = [ct.c_void_p]

for f in library_functions:
	if getattr(libcoap, f["name"], None) is None:
		if verbosity > 0:
			print(f["name"], "not found in library")
		continue
	
	def function_factory(f=f):
		def dyn_fct(*nargs, **kwargs):
			if "args" in f:
				if isinstance(f["args"], list):
					args = f["args"]
				else:
					args = f["args"].values()
			else:
				args = None
			if "restype" in f:
				restype = f["restype"]
			else:
				restype = ct.c_int
			
			return ct_call(f["name"], *nargs, args=args, restype=restype)
		
		if "expect" in f:
			dyn_fct.expect = f["expect"]
		if "res_error" in f:
			dyn_fct.expect = f["res_error"]
		
		return dyn_fct
	
	if hasattr(sys.modules[__name__], f["name"]):
		print("duplicate function", f["name"], file=sys.stderr)
	
	setattr(sys.modules[__name__], f["name"], function_factory(f))

if sys.version_info < (3,):
	def to_bytes(x):
		return x
else:
	def to_bytes(s):
		if isinstance(s, str):
			return s.encode()
		else:
			return s

def ct_call(*nargs, **kwargs):
	call = nargs[0]
	
	if "args" in kwargs:
		args = kwargs["args"]
	else:
		args = None
	if "check" in kwargs:
		check = kwargs["check"]
	else:
		check = None
	
	nargs = nargs[1:]
	
	func = getattr(libcoap, call)
	if args:
		func.argtypes = args
	if "restype" in kwargs:
		func.restype = kwargs["restype"]
	
	newargs = tuple()
	for i in range(len(nargs)):
		newargs += (to_bytes(nargs[i]), )
	
	#print(call, newargs)
	res = func(*newargs)
	
	if verbosity > 1:
		print(call, newargs, "=", res)
	
	if (check is None or check):
		if hasattr(func, "expect") and res != func.expect:
			if func.restype in [ct.c_long, ct.c_int] and res < 0:
				raise OSError(res, call+" failed with: "+os.strerror(-res)+" ("+str(-res)+")")
			else:
				raise OSError(res, call+" failed with: "+str(res)+" (!="+str(func.expect)+")")
		elif hasattr(func, "res_error") and res == func.res_error:
			raise OSError(res, call+" failed with: "+str(res)+" (=="+str(func.res_error)+")")
		elif func.restype in [ct.c_long, ct.c_int] and res < 0:
			raise OSError(res, call+" failed with: "+os.strerror(-res)+" ("+str(-res)+")")
		elif isinstance(res, ct._Pointer) and not res:
			raise NullPointer(call+" returned NULL pointer")
	if check and isinstance(func.restype, ct.POINTER) and res == None:
		raise OSError(res, call+" returned NULL")
	
	return res

if __name__ == "__main__":
	coap_startup()
	
	if len(sys.argv) < 2:
		uri_str = b"coap://localhost/.well-known/core"
	else:
		uri_str = sys.argv[1].encode()
	uri_t = coap_uri_t()
	
	coap_split_uri(ct.cast(ct.c_char_p(uri_str), c_uint8_p), len(uri_str), ct.byref(uri_t))
	
	ctx = coap_new_context(None);
	
	coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
	
	import socket
	addr_info = coap_resolve_address_info(ct.byref(uri_t.host), uri_t.port, uri_t.port, uri_t.port, uri_t.port,
		socket.AF_UNSPEC, 1 << uri_t.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
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
	
	pdu = coap_pdu_init(COAP_MESSAGE_CON,
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
