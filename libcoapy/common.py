
import weakref

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

def allocateToken():
	token = coap_binary_t()
	token.length = 8
	
	token_t = ct.c_ubyte * token.length
	token.s = token_t()
	
	return token

class UnresolvableAddress(Exception):
	def __init__(self, uri, context=None):
		self.uri = uri
		self.ctx = context

class CoapUnexpectedError(Exception):
	pass
