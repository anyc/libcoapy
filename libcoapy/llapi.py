
import os, sys, enum
import ctypes as ct

class NullPointer(Exception):
	pass


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
	
	# Looks like number types get converted to type "int". We have to use this
	# workaround to access the actual ctype of a field.
	# https://stackoverflow.com/questions/71802792/why-does-ctypes-c-int-completely-change-its-behaviour-when-put-into-ctypes-struc
	def ctype(self, field):
		ftype=None
		for fname, ftype in self._fields_:
			if fname == field:
				t = ftype
				break
		return ftype.from_buffer(self, getattr(self.__class__, field).offset)
	
	@classmethod
	def set_fields(cls, fields):
		cls._fields_ = [ (name, typ) for typ, name in fields ]

class ctypes_enum_gen(enum.IntEnum):
	@classmethod
	def from_param(cls, param):
		return ct.c_int(param)
	
	@classmethod
	def get_ctype(cls):
		return ct.c_int
	
	def __str__(self):
		return self.name

class coap_pdu_t(LStructure):
	pass

class coap_context_t(LStructure):
	pass

class coap_resource_t(LStructure):
	pass

class coap_session_t(LStructure):
	pass

class coap_oscore_conf_t(LStructure):
	pass

class coap_subscription_t(LStructure):
	pass

class coap_endpoint_t(LStructure):
	pass

class coap_socket_t(LStructure):
	pass

class coap_async_t(LStructure):
	pass

class coap_cache_key_t(LStructure):
	pass

class coap_cache_entry_t(LStructure):
	pass

class coap_attr_t(LStructure):
	pass

class fd_set(LStructure):
	pass

class epoll_event(LStructure):
	pass


library_functions = []


# from sockaddr.py

class sockaddr(ct.Structure):
	_fields_ = [
		("sa_family", ct.c_short),
		("sa_data", ct.c_byte * 14)
		]

class sockaddr_in(ct.Structure):
	_fields_ = [
		("sin_family", ct.c_short),
		("sin_port", ct.c_ushort),
		("sin_addr", ct.c_byte * 4),
		("sin_zero", ct.c_byte * 8)
		]

class sockaddr_in6(ct.Structure):
	_fields_ = [
		("sin6_family", ct.c_short),
		("sin6_port", ct.c_ushort),
		("sin6_flowinfo", ct.c_uint32),
		("sin6_addr", ct.c_byte * 16),
		("sin6_scope_id", ct.c_uint32),
		]


# from local.py

COAP_IO_NO_WAIT = ct.c_uint32(-1).value

libcoap_initialized = False

def genbindgen_pre_ct_call_hook(fdict, nargs, kwargs):
	global libcoap_initialized
	
	if not libcoap_initialized:
		libcoap_initialized = True
		coap_startup()

def bytes2uint8p(b, cast=ct.POINTER(ct.c_ubyte)):
	if b is None:
		return None
	return ct.cast(ct.create_string_buffer(b), cast)

def c_uint8_p_to_str(uint8p, length):
	b = ct.string_at(uint8p, length)
	try:
		return b.decode()
	except:
		return b

class coap_string_t(LStructure):
	_fields_ = [("length", ct.c_size_t), ("s", ct.POINTER(ct.c_uint8))]
	
	def __init__(self, value=None):
		super().__init__()
		
		if value:
			if isinstance(value, str):
				b = value.encode()
			else:
				b = value
			
			self.s = bytes2uint8p(b)
			self.length = ct.c_size_t(len(b))
	
	def __str__(self):
		return str(c_uint8_p_to_str(self.s, self.length))

class coap_str_const_t(coap_string_t):
	pass

class coap_binary_t(coap_string_t):
	def __str__(self):
		return str([ "0x%02x" % (self.s[i]) for i in range(self.length)])

class coap_bin_const_t(coap_binary_t):
	pass


class coap_option_t(LStructure):
	pass

class coap_opt_filter_t(LStructure):
	pass

class coap_opt_iterator_t(LStructure):
	pass

class coap_optlist_t(LStructure):
	pass

class coap_const_char_ptr_t(ct.Union):
	pass

class coap_uri_t(LStructure):
	pass

class coap_option(LStructure):
	pass

class coap_sockaddr_un(LStructure):
	pass

class coap_address_t_addr(ct.Union):
	pass

class coap_address_t(LStructure):
	pass

class coap_addr_info_t(LStructure):
	pass

class coap_addr_tuple_t(LStructure):
	pass

class coap_tls_version_t(LStructure):
	pass

class coap_pki_key_pem_t(LStructure):
	pass

class coap_pki_key_pem_buf_t(LStructure):
	pass

class coap_pki_key_asn1_t(LStructure):
	pass

class coap_pki_key_pkcs11_t(LStructure):
	pass

class coap_pki_key_define_t(LStructure):
	pass

class coap_dtls_key_t_key(ct.Union):
	pass

class coap_dtls_key_t(LStructure):
	pass

class coap_dtls_pki_t(LStructure):
	pass

class coap_dtls_cpsk_info_t(LStructure):
	pass

class coap_dtls_cpsk_t(LStructure):
	pass

class coap_dtls_spsk_info_t(LStructure):
	pass

class coap_dtls_spsk_t(LStructure):
	pass

class coap_fixed_point_t(LStructure):
	pass

class coap_block_t(LStructure):
	pass

class coap_block_b_t(LStructure):
	pass

class coap_proxy_server_t(LStructure):
	pass

class coap_proxy_server_list_t(LStructure):
	pass

LIBCOAP_PACKAGE_BUGREPORT = "libcoap-developers@lists.sourceforge.net";
LIBCOAP_PACKAGE_NAME = "libcoap";
LIBCOAP_PACKAGE_STRING = "libcoap 4.3.5";
LIBCOAP_PACKAGE_URL = "https://libcoap.net/";
LIBCOAP_PACKAGE_VERSION = "4.3.5";
COAP_OPT_FILTER_SHORT = 6;
COAP_OPT_FILTER_LONG = 2;
COAP_OPT_ALL = None;
COAP_MAX_STR_CONST_FUNC = 2;
COAP_URI_SCHEME_SECURE_MASK = 0x01;
COAP_DEFAULT_PORT = 5683;
COAPS_DEFAULT_PORT = 5684;
COAP_DEFAULT_MAX_AGE = 60;
COAP_DEFAULT_MTU = 1152;
COAP_BERT_BASE = 1152;
COAP_DEFAULT_HOP_LIMIT = 16;
COAP_DEFAULT_SCHEME = "coap";
COAP_DEFAULT_URI_WELLKNOWN = ".well-known/core";
COAP_TOKEN_DEFAULT_MAX = 8;
COAP_TOKEN_EXT_MAX = 4096;
COAP_OPTION_IF_MATCH = 1;
COAP_OPTION_URI_HOST = 3;
COAP_OPTION_ETAG = 4;
COAP_OPTION_IF_NONE_MATCH = 5;
COAP_OPTION_OBSERVE = 6;
COAP_OPTION_URI_PORT = 7;
COAP_OPTION_LOCATION_PATH = 8;
COAP_OPTION_OSCORE = 9;
COAP_OPTION_URI_PATH = 11;
COAP_OPTION_CONTENT_FORMAT = 12;
COAP_OPTION_MAXAGE = 14;
COAP_OPTION_URI_QUERY = 15;
COAP_OPTION_HOP_LIMIT = 16;
COAP_OPTION_ACCEPT = 17;
COAP_OPTION_Q_BLOCK1 = 19;
COAP_OPTION_LOCATION_QUERY = 20;
COAP_OPTION_EDHOC = 21;
COAP_OPTION_BLOCK2 = 23;
COAP_OPTION_BLOCK1 = 27;
COAP_OPTION_SIZE2 = 28;
COAP_OPTION_Q_BLOCK2 = 31;
COAP_OPTION_PROXY_URI = 35;
COAP_OPTION_PROXY_SCHEME = 39;
COAP_OPTION_SIZE1 = 60;
COAP_OPTION_ECHO = 252;
COAP_OPTION_NORESPONSE = 258;
COAP_OPTION_RTAG = 292;
COAP_MAX_OPT = 65534;
COAP_ERROR_PHRASE_LENGTH = 32;
COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE = 2;
COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER = 4;
COAP_SIGNALING_OPTION_EXTENDED_TOKEN_LENGTH = 6;
COAP_SIGNALING_OPTION_CUSTODY = 2;
COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS = 2;
COAP_SIGNALING_OPTION_HOLD_OFF = 4;
COAP_SIGNALING_OPTION_BAD_CSM_OPTION = 2;
COAP_MEDIATYPE_TEXT_PLAIN = 0;
COAP_MEDIATYPE_APPLICATION_LINK_FORMAT = 40;
COAP_MEDIATYPE_APPLICATION_XML = 41;
COAP_MEDIATYPE_APPLICATION_OCTET_STREAM = 42;
COAP_MEDIATYPE_APPLICATION_RDF_XML = 43;
COAP_MEDIATYPE_APPLICATION_EXI = 47;
COAP_MEDIATYPE_APPLICATION_JSON = 50;
COAP_MEDIATYPE_APPLICATION_CBOR = 60;
COAP_MEDIATYPE_APPLICATION_CWT = 61;
COAP_MEDIATYPE_APPLICATION_COAP_GROUP_JSON = 256;
COAP_MEDIATYPE_APPLICATION_COSE_SIGN = 98;
COAP_MEDIATYPE_APPLICATION_COSE_SIGN1 = 18;
COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT = 96;
COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0 = 16;
COAP_MEDIATYPE_APPLICATION_COSE_MAC = 97;
COAP_MEDIATYPE_APPLICATION_COSE_MAC0 = 17;
COAP_MEDIATYPE_APPLICATION_COSE_KEY = 101;
COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET = 102;
COAP_MEDIATYPE_APPLICATION_SENML_JSON = 110;
COAP_MEDIATYPE_APPLICATION_SENSML_JSON = 111;
COAP_MEDIATYPE_APPLICATION_SENML_CBOR = 112;
COAP_MEDIATYPE_APPLICATION_SENSML_CBOR = 113;
COAP_MEDIATYPE_APPLICATION_SENML_EXI = 114;
COAP_MEDIATYPE_APPLICATION_SENSML_EXI = 115;
COAP_MEDIATYPE_APPLICATION_SENML_XML = 310;
COAP_MEDIATYPE_APPLICATION_SENSML_XML = 311;
COAP_MEDIATYPE_APPLICATION_DOTS_CBOR = 271;
COAP_MEDIATYPE_APPLICATION_ACE_CBOR = 19;
COAP_MEDIATYPE_APPLICATION_MB_CBOR_SEQ = 272;
COAP_MEDIATYPE_APPLICATION_OSCORE = 10001;
COAP_INVALID_MID = -1;
COAP_RXBUFFER_SIZE = 1472;
COAP_MAX_EPOLL_EVENTS = 10;
COAP_DTLS_HINT_LENGTH = 128;
COAP_DTLS_MAX_PSK_IDENTITY = 64;
COAP_DTLS_MAX_PSK = 64;
COAP_DTLS_RPK_CERT_CN = "RPK";
COAP_DTLS_PKI_SETUP_VERSION = 1;
COAP_DTLS_CPSK_SETUP_VERSION = 1;
COAP_DTLS_SPSK_SETUP_VERSION = 1;
COAP_MAX_LOGGING_LEVEL = 8;
_COAP_LOG_EMERG = 0;
_COAP_LOG_ALERT = 1;
_COAP_LOG_CRIT = 2;
_COAP_LOG_ERR = 3;
_COAP_LOG_WARN = 4;
_COAP_LOG_NOTICE = 5;
_COAP_LOG_INFO = 6;
_COAP_LOG_DEBUG = 7;
_COAP_LOG_OSCORE = 8;
COAP_IO_WAIT = 0;
COAP_MAX_BLOCK_SZX = 6;
COAP_BLOCK_USE_LIBCOAP = 0x01;
COAP_BLOCK_SINGLE_BODY = 0x02;
COAP_BLOCK_TRY_Q_BLOCK = 0x04;
COAP_BLOCK_USE_M_Q_BLOCK = 0x08;
COAP_BLOCK_NO_PREEMPTIVE_RTAG = 0x10;
COAP_BLOCK_STLESS_FETCH = 0x20;
COAP_BLOCK_STLESS_BLOCK2 = 0x40;
COAP_BLOCK_NOT_RANDOM_BLOCK1 = 0x80;
COAP_BLOCK_CACHE_RESPONSE = 0x100;
COAP_RESOURCE_CHECK_TIME = 2;
COAP_ATTR_FLAGS_RELEASE_NAME = 0x1;
COAP_ATTR_FLAGS_RELEASE_VALUE = 0x2;
COAP_RESOURCE_FLAGS_RELEASE_URI = 0x1;
COAP_RESOURCE_FLAGS_NOTIFY_NON = 0x0;
COAP_RESOURCE_FLAGS_NOTIFY_CON = 0x2;
COAP_RESOURCE_FLAGS_NOTIFY_NON_ALWAYS = 0x4;
COAP_RESOURCE_FLAGS_HAS_MCAST_SUPPORT = 0x8;
COAP_RESOURCE_FLAGS_LIB_DIS_MCAST_DELAYS = 0x10;
COAP_RESOURCE_FLAGS_LIB_ENA_MCAST_SUPPRESS_2_05 = 0x20;
COAP_RESOURCE_FLAGS_LIB_ENA_MCAST_SUPPRESS_2_XX = 0x40;
COAP_RESOURCE_FLAGS_LIB_DIS_MCAST_SUPPRESS_4_XX = 0x80;
COAP_RESOURCE_FLAGS_LIB_DIS_MCAST_SUPPRESS_5_XX = 0x100;
COAP_RESOURCE_FLAGS_FORCE_SINGLE_BODY = 0x200;
COAP_RESOURCE_FLAGS_OSCORE_ONLY = 0x400;
COAP_RESOURCE_HANDLE_WELLKNOWN_CORE = 0x800;
COAP_OBSERVE_ESTABLISH = 0;
COAP_OBSERVE_CANCEL = 1;
coap_option_num_t = ct.c_ushort
coap_opt_t = ct.c_uint8
coap_option_t._fields_ = [
	("delta", ct.c_ushort),
	("length", ct.c_size_t),
	("value", ct.POINTER(ct.c_uint8)),
	]

coap_opt_filter_t._fields_ = [
	("mask", ct.c_ushort),
	("long_opts", ct.c_ushort * 2),
	("short_opts", ct.c_uint8 * 6),
	]

coap_opt_iterator_t._fields_ = [
	("length", ct.c_size_t),
	("number", ct.c_ushort),
	("bad", ct.c_uint),
	("filtered", ct.c_uint),
	("next_option", ct.POINTER(ct.c_uint8)),
	("filter", coap_opt_filter_t),
	]

coap_optlist_t._fields_ = [
	("next", ct.POINTER(coap_optlist_t)),
	("number", ct.c_ushort),
	("length", ct.c_size_t),
	("data", ct.POINTER(ct.c_uint8)),
	]

coap_const_char_ptr_t._fields_ = [
	("s_byte", ct.c_char_p),
	("u_byte", ct.POINTER(ct.c_uint8)),
	]

class coap_uri_scheme_t(ctypes_enum_gen):
	COAP_URI_SCHEME_COAP = 0
	COAP_URI_SCHEME_COAPS = 1
	COAP_URI_SCHEME_COAP_TCP = 2
	COAP_URI_SCHEME_COAPS_TCP = 3
	COAP_URI_SCHEME_HTTP = 4
	COAP_URI_SCHEME_HTTPS = 5
	COAP_URI_SCHEME_COAP_WS = 6
	COAP_URI_SCHEME_COAPS_WS = 7
	COAP_URI_SCHEME_LAST = 8

coap_uri_t._fields_ = [
	("host", coap_str_const_t),
	("port", ct.c_ushort),
	("path", coap_str_const_t),
	("query", coap_str_const_t),
	("scheme", coap_uri_scheme_t.get_ctype()),
	]

class coap_pdu_type_t(ctypes_enum_gen):
	COAP_MESSAGE_CON = 0
	COAP_MESSAGE_NON = 1
	COAP_MESSAGE_ACK = 2
	COAP_MESSAGE_RST = 3

class coap_request_t(ctypes_enum_gen):
	COAP_REQUEST_GET = 1
	COAP_REQUEST_POST = 2
	COAP_REQUEST_PUT = 3
	COAP_REQUEST_DELETE = 4
	COAP_REQUEST_FETCH = 5
	COAP_REQUEST_PATCH = 6
	COAP_REQUEST_IPATCH = 7

class coap_pdu_signaling_proto_t(ctypes_enum_gen):
	COAP_SIGNALING_CSM = 225
	COAP_SIGNALING_PING = 226
	COAP_SIGNALING_PONG = 227
	COAP_SIGNALING_RELEASE = 228
	COAP_SIGNALING_ABORT = 229

coap_mid_t = ct.c_int
coap_option._fields_ = [
	("key", ct.c_ushort),
	("length", ct.c_uint),
	]

class coap_proto_t(ctypes_enum_gen):
	COAP_PROTO_NONE = 0
	COAP_PROTO_UDP = 1
	COAP_PROTO_DTLS = 2
	COAP_PROTO_TCP = 3
	COAP_PROTO_TLS = 4
	COAP_PROTO_WS = 5
	COAP_PROTO_WSS = 6
	COAP_PROTO_LAST = 7

class coap_pdu_code_t(ctypes_enum_gen):
	COAP_EMPTY_CODE = 0
	COAP_REQUEST_CODE_GET = 1
	COAP_REQUEST_CODE_POST = 2
	COAP_REQUEST_CODE_PUT = 3
	COAP_REQUEST_CODE_DELETE = 4
	COAP_REQUEST_CODE_FETCH = 5
	COAP_REQUEST_CODE_PATCH = 6
	COAP_REQUEST_CODE_IPATCH = 7
	COAP_RESPONSE_CODE_CREATED = 65
	COAP_RESPONSE_CODE_DELETED = 66
	COAP_RESPONSE_CODE_VALID = 67
	COAP_RESPONSE_CODE_CHANGED = 68
	COAP_RESPONSE_CODE_CONTENT = 69
	COAP_RESPONSE_CODE_CONTINUE = 95
	COAP_RESPONSE_CODE_BAD_REQUEST = 128
	COAP_RESPONSE_CODE_UNAUTHORIZED = 129
	COAP_RESPONSE_CODE_BAD_OPTION = 130
	COAP_RESPONSE_CODE_FORBIDDEN = 131
	COAP_RESPONSE_CODE_NOT_FOUND = 132
	COAP_RESPONSE_CODE_NOT_ALLOWED = 133
	COAP_RESPONSE_CODE_NOT_ACCEPTABLE = 134
	COAP_RESPONSE_CODE_INCOMPLETE = 136
	COAP_RESPONSE_CODE_CONFLICT = 137
	COAP_RESPONSE_CODE_PRECONDITION_FAILED = 140
	COAP_RESPONSE_CODE_REQUEST_TOO_LARGE = 141
	COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT = 143
	COAP_RESPONSE_CODE_UNPROCESSABLE = 150
	COAP_RESPONSE_CODE_TOO_MANY_REQUESTS = 157
	COAP_RESPONSE_CODE_INTERNAL_ERROR = 160
	COAP_RESPONSE_CODE_NOT_IMPLEMENTED = 161
	COAP_RESPONSE_CODE_BAD_GATEWAY = 162
	COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE = 163
	COAP_RESPONSE_CODE_GATEWAY_TIMEOUT = 164
	COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED = 165
	COAP_RESPONSE_CODE_HOP_LIMIT_REACHED = 168
	COAP_SIGNALING_CODE_CSM = 225
	COAP_SIGNALING_CODE_PING = 226
	COAP_SIGNALING_CODE_PONG = 227
	COAP_SIGNALING_CODE_RELEASE = 228
	COAP_SIGNALING_CODE_ABORT = 229

coap_sockaddr_un._fields_ = [
	("sun_family", ct.c_ushort),
	("sun_path", ct.c_int8 * 26),
	]

coap_address_t_addr._fields_ = [
	("sa", sockaddr),
	("sin", sockaddr_in),
	("sin6", sockaddr_in6),
	("cun", coap_sockaddr_un),
	]

coap_address_t._fields_ = [
	("size", ct.c_uint),
	("addr", coap_address_t_addr),
	]

coap_addr_info_t._fields_ = [
	("next", ct.POINTER(coap_addr_info_t)),
	("scheme", coap_uri_scheme_t.get_ctype()),
	("proto", coap_proto_t.get_ctype()),
	("addr", coap_address_t),
	]

class coap_resolve_type_t(ctypes_enum_gen):
	COAP_RESOLVE_TYPE_LOCAL = 0
	COAP_RESOLVE_TYPE_REMOTE = 1

coap_fd_t = ct.c_int
coap_socket_flags_t = ct.c_ushort
coap_addr_tuple_t._fields_ = [
	("remote", coap_address_t),
	("local", coap_address_t),
	]

class coap_nack_reason_t(ctypes_enum_gen):
	COAP_NACK_TOO_MANY_RETRIES = 0
	COAP_NACK_NOT_DELIVERABLE = 1
	COAP_NACK_RST = 2
	COAP_NACK_TLS_FAILED = 3
	COAP_NACK_ICMP_ISSUE = 4
	COAP_NACK_BAD_RESPONSE = 5
	COAP_NACK_TLS_LAYER_FAILED = 6
	COAP_NACK_WS_LAYER_FAILED = 7
	COAP_NACK_WS_FAILED = 8

coap_tick_t = ct.c_ulong
coap_time_t = ct.c_long
coap_tick_diff_t = ct.c_long
class coap_dtls_role_t(ctypes_enum_gen):
	COAP_DTLS_ROLE_CLIENT = 0
	COAP_DTLS_ROLE_SERVER = 1

class coap_tls_library_t(ctypes_enum_gen):
	COAP_TLS_LIBRARY_NOTLS = 0
	COAP_TLS_LIBRARY_TINYDTLS = 1
	COAP_TLS_LIBRARY_OPENSSL = 2
	COAP_TLS_LIBRARY_GNUTLS = 3
	COAP_TLS_LIBRARY_MBEDTLS = 4
	COAP_TLS_LIBRARY_WOLFSSL = 5

coap_tls_version_t._fields_ = [
	("version", ct.c_ulong),
	("type", coap_tls_library_t.get_ctype()),
	("built_version", ct.c_ulong),
	]

coap_dtls_security_setup_t = ct.CFUNCTYPE(ct.c_int, ct.py_object, ct.POINTER(coap_dtls_pki_t))
coap_dtls_cn_callback_t = ct.CFUNCTYPE(ct.c_int, ct.c_char_p, ct.POINTER(ct.c_uint8), ct.c_ulong, ct.POINTER(coap_session_t), ct.c_uint, ct.c_int, ct.py_object)
class coap_asn1_privatekey_type_t(ctypes_enum_gen):
	COAP_ASN1_PKEY_NONE = 0
	COAP_ASN1_PKEY_RSA = 1
	COAP_ASN1_PKEY_RSA2 = 2
	COAP_ASN1_PKEY_DSA = 3
	COAP_ASN1_PKEY_DSA1 = 4
	COAP_ASN1_PKEY_DSA2 = 5
	COAP_ASN1_PKEY_DSA3 = 6
	COAP_ASN1_PKEY_DSA4 = 7
	COAP_ASN1_PKEY_DH = 8
	COAP_ASN1_PKEY_DHX = 9
	COAP_ASN1_PKEY_EC = 10
	COAP_ASN1_PKEY_HMAC = 11
	COAP_ASN1_PKEY_CMAC = 12
	COAP_ASN1_PKEY_TLS1_PRF = 13
	COAP_ASN1_PKEY_HKDF = 14

class coap_pki_key_t(ctypes_enum_gen):
	COAP_PKI_KEY_PEM = 0
	COAP_PKI_KEY_ASN1 = 1
	COAP_PKI_KEY_PEM_BUF = 2
	COAP_PKI_KEY_PKCS11 = 3
	COAP_PKI_KEY_DEFINE = 4

coap_pki_key_pem_t._fields_ = [
	("ca_file", ct.c_char_p),
	("public_cert", ct.c_char_p),
	("private_key", ct.c_char_p),
	]

coap_pki_key_pem_buf_t._fields_ = [
	("ca_cert", ct.POINTER(ct.c_uint8)),
	("public_cert", ct.POINTER(ct.c_uint8)),
	("private_key", ct.POINTER(ct.c_uint8)),
	("ca_cert_len", ct.c_size_t),
	("public_cert_len", ct.c_size_t),
	("private_key_len", ct.c_size_t),
	]

coap_pki_key_asn1_t._fields_ = [
	("ca_cert", ct.POINTER(ct.c_uint8)),
	("public_cert", ct.POINTER(ct.c_uint8)),
	("private_key", ct.POINTER(ct.c_uint8)),
	("ca_cert_len", ct.c_size_t),
	("public_cert_len", ct.c_size_t),
	("private_key_len", ct.c_size_t),
	("private_key_type", coap_asn1_privatekey_type_t.get_ctype()),
	]

coap_pki_key_pkcs11_t._fields_ = [
	("ca", ct.c_char_p),
	("public_cert", ct.c_char_p),
	("private_key", ct.c_char_p),
	("user_pin", ct.c_char_p),
	]

class coap_pki_define_t(ctypes_enum_gen):
	COAP_PKI_KEY_DEF_PEM = 0
	COAP_PKI_KEY_DEF_PEM_BUF = 1
	COAP_PKI_KEY_DEF_RPK_BUF = 2
	COAP_PKI_KEY_DEF_DER = 3
	COAP_PKI_KEY_DEF_DER_BUF = 4
	COAP_PKI_KEY_DEF_PKCS11 = 5
	COAP_PKI_KEY_DEF_PKCS11_RPK = 6
	COAP_PKI_KEY_DEF_ENGINE = 7

coap_pki_key_define_t._fields_ = [
	("ca", coap_const_char_ptr_t),
	("public_cert", coap_const_char_ptr_t),
	("private_key", coap_const_char_ptr_t),
	("ca_len", ct.c_size_t),
	("public_cert_len", ct.c_size_t),
	("private_key_len", ct.c_size_t),
	("ca_def", coap_pki_define_t.get_ctype()),
	("public_cert_def", coap_pki_define_t.get_ctype()),
	("private_key_def", coap_pki_define_t.get_ctype()),
	("private_key_type", coap_asn1_privatekey_type_t.get_ctype()),
	("user_pin", ct.c_char_p),
	]

coap_dtls_key_t_key._fields_ = [
	("pem", coap_pki_key_pem_t),
	("pem_buf", coap_pki_key_pem_buf_t),
	("asn1", coap_pki_key_asn1_t),
	("pkcs11", coap_pki_key_pkcs11_t),
	("define", coap_pki_key_define_t),
	]

coap_dtls_key_t._fields_ = [
	("key_type", coap_pki_key_t.get_ctype()),
	("key", coap_dtls_key_t_key),
	]

coap_dtls_pki_sni_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.c_char_p, ct.py_object)
coap_dtls_pki_t._fields_ = [
	("version", ct.c_uint8),
	("verify_peer_cert", ct.c_uint8),
	("check_common_ca", ct.c_uint8),
	("allow_self_signed", ct.c_uint8),
	("allow_expired_certs", ct.c_uint8),
	("cert_chain_validation", ct.c_uint8),
	("cert_chain_verify_depth", ct.c_uint8),
	("check_cert_revocation", ct.c_uint8),
	("allow_no_crl", ct.c_uint8),
	("allow_expired_crl", ct.c_uint8),
	("allow_bad_md_hash", ct.c_uint8),
	("allow_short_rsa_length", ct.c_uint8),
	("is_rpk_not_cert", ct.c_uint8),
	("use_cid", ct.c_uint8),
	("reserved", ct.c_uint8 * 2),
	("validate_cn_call_back", coap_dtls_cn_callback_t),
	("cn_call_back_arg", ct.py_object),
	("validate_sni_call_back", coap_dtls_pki_sni_callback_t),
	("sni_call_back_arg", ct.py_object),
	("additional_tls_setup_call_back", coap_dtls_security_setup_t),
	("client_sni", ct.c_char_p),
	("pki_key", coap_dtls_key_t),
	]

coap_dtls_cpsk_info_t._fields_ = [
	("identity", coap_bin_const_t),
	("key", coap_bin_const_t),
	]

coap_dtls_ih_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_str_const_t), ct.POINTER(coap_session_t), ct.py_object)
coap_dtls_cpsk_t._fields_ = [
	("version", ct.c_uint8),
	("ec_jpake", ct.c_uint8),
	("use_cid", ct.c_uint8),
	("reserved", ct.c_uint8 * 5),
	("validate_ih_call_back", coap_dtls_ih_callback_t),
	("ih_call_back_arg", ct.py_object),
	("client_sni", ct.c_char_p),
	("psk_info", coap_dtls_cpsk_info_t),
	]

coap_dtls_spsk_info_t._fields_ = [
	("hint", coap_bin_const_t),
	("key", coap_bin_const_t),
	]

coap_dtls_id_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_bin_const_t), ct.POINTER(coap_session_t), ct.py_object)
coap_dtls_psk_sni_callback_t = ct.CFUNCTYPE(ct.c_void_p, ct.c_char_p, ct.POINTER(coap_session_t), ct.py_object)
coap_dtls_spsk_t._fields_ = [
	("version", ct.c_uint8),
	("ec_jpake", ct.c_uint8),
	("reserved", ct.c_uint8 * 6),
	("validate_id_call_back", coap_dtls_id_callback_t),
	("id_call_back_arg", ct.py_object),
	("validate_sni_call_back", coap_dtls_psk_sni_callback_t),
	("sni_call_back_arg", ct.py_object),
	("psk_info", coap_dtls_spsk_info_t),
	]

class coap_event_t(ctypes_enum_gen):
	COAP_EVENT_DTLS_CLOSED = 0
	COAP_EVENT_DTLS_CONNECTED = 478
	COAP_EVENT_DTLS_RENEGOTIATE = 479
	COAP_EVENT_DTLS_ERROR = 512
	COAP_EVENT_TCP_CONNECTED = 4097
	COAP_EVENT_TCP_CLOSED = 4098
	COAP_EVENT_TCP_FAILED = 4099
	COAP_EVENT_SESSION_CONNECTED = 8193
	COAP_EVENT_SESSION_CLOSED = 8194
	COAP_EVENT_SESSION_FAILED = 8195
	COAP_EVENT_PARTIAL_BLOCK = 12289
	COAP_EVENT_XMIT_BLOCK_FAIL = 12290
	COAP_EVENT_SERVER_SESSION_NEW = 16385
	COAP_EVENT_SERVER_SESSION_DEL = 16386
	COAP_EVENT_SERVER_SESSION_CONNECTED = 16387
	COAP_EVENT_BAD_PACKET = 20481
	COAP_EVENT_MSG_RETRANSMITTED = 20482
	COAP_EVENT_OSCORE_DECRYPTION_FAILURE = 24577
	COAP_EVENT_OSCORE_NOT_ENABLED = 24578
	COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD = 24579
	COAP_EVENT_OSCORE_NO_SECURITY = 24580
	COAP_EVENT_OSCORE_INTERNAL_ERROR = 24581
	COAP_EVENT_OSCORE_DECODE_ERROR = 24582
	COAP_EVENT_WS_PACKET_SIZE = 28673
	COAP_EVENT_WS_CONNECTED = 28674
	COAP_EVENT_WS_CLOSED = 28675
	COAP_EVENT_KEEPALIVE_FAILURE = 32769

coap_event_handler_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_session_t), coap_event_t.get_ctype())
coap_fixed_point_t._fields_ = [
	("integer_part", ct.c_ushort),
	("fractional_part", ct.c_ushort),
	]

class coap_session_type_t(ctypes_enum_gen):
	COAP_SESSION_TYPE_NONE = 0
	COAP_SESSION_TYPE_CLIENT = 1
	COAP_SESSION_TYPE_SERVER = 2
	COAP_SESSION_TYPE_HELLO = 3

class coap_session_state_t(ctypes_enum_gen):
	COAP_SESSION_STATE_NONE = 0
	COAP_SESSION_STATE_CONNECTING = 1
	COAP_SESSION_STATE_HANDSHAKE = 2
	COAP_SESSION_STATE_CSM = 3
	COAP_SESSION_STATE_ESTABLISHED = 4

coap_app_data_free_callback_t = ct.CFUNCTYPE(None, ct.py_object)
class coap_log_t(ctypes_enum_gen):
	COAP_LOG_EMERG = 0
	COAP_LOG_ALERT = 1
	COAP_LOG_CRIT = 2
	COAP_LOG_ERR = 3
	COAP_LOG_WARN = 4
	COAP_LOG_NOTICE = 5
	COAP_LOG_INFO = 6
	COAP_LOG_DEBUG = 7
	COAP_LOG_OSCORE = 8
	COAP_LOG_DTLS_BASE = 9

coap_log_handler_t = ct.CFUNCTYPE(None, coap_log_t.get_ctype(), ct.c_char_p)
class coap_response_t(ctypes_enum_gen):
	COAP_RESPONSE_FAIL = 0
	COAP_RESPONSE_OK = 1

coap_response_handler_t = ct.CFUNCTYPE(coap_response_t.get_ctype(), ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.POINTER(coap_pdu_t), ct.c_int)
coap_nack_handler_t = ct.CFUNCTYPE(None, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), coap_nack_reason_t.get_ctype(), ct.c_int)
coap_ping_handler_t = ct.CFUNCTYPE(None, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.c_int)
coap_pong_handler_t = ct.CFUNCTYPE(None, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.c_int)
coap_resource_dynamic_create_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t))
coap_io_process_thread_t = ct.CFUNCTYPE(None, ct.py_object)
coap_block_t._fields_ = [
	("num", ct.c_uint),
	("m", ct.c_uint),
	("szx", ct.c_uint),
	]

coap_block_b_t._fields_ = [
	("num", ct.c_uint),
	("m", ct.c_uint),
	("szx", ct.c_uint),
	("aszx", ct.c_uint),
	("defined", ct.c_uint),
	("bert", ct.c_uint),
	("chunk_size", ct.c_uint),
	]

coap_release_large_data_t = ct.CFUNCTYPE(None, ct.POINTER(coap_session_t), ct.py_object)
coap_cache_app_data_free_callback_t = ct.CFUNCTYPE(None, ct.py_object)
class coap_cache_session_based_t(ctypes_enum_gen):
	COAP_CACHE_NOT_SESSION_BASED = 0
	COAP_CACHE_IS_SESSION_BASED = 1

class coap_cache_record_pdu_t(ctypes_enum_gen):
	COAP_CACHE_NOT_RECORD_PDU = 0
	COAP_CACHE_RECORD_PDU = 1

coap_oscore_save_seq_num_t = ct.CFUNCTYPE(ct.c_int, ct.c_ulong, ct.py_object)
class coap_proxy_t(ctypes_enum_gen):
	COAP_PROXY_REVERSE = 0
	COAP_PROXY_REVERSE_STRIP = 1
	COAP_PROXY_FORWARD_STATIC = 2
	COAP_PROXY_FORWARD_STATIC_STRIP = 3
	COAP_PROXY_FORWARD_DYNAMIC = 4
	COAP_PROXY_FORWARD_DYNAMIC_STRIP = 5
	COAP_PROXY_FORWARD = 2
	COAP_PROXY_FORWARD_STRIP = 3
	COAP_PROXY_DIRECT = 4
	COAP_PROXY_DIRECT_STRIP = 5

coap_proxy_server_t._fields_ = [
	("uri", coap_uri_t),
	("dtls_pki", ct.POINTER(coap_dtls_pki_t)),
	("dtls_cpsk", ct.POINTER(coap_dtls_cpsk_t)),
	("oscore_conf", ct.POINTER(coap_oscore_conf_t)),
	]

coap_proxy_server_list_t._fields_ = [
	("entry", ct.POINTER(coap_proxy_server_t)),
	("entry_count", ct.c_size_t),
	("next_entry", ct.c_size_t),
	("type", coap_proxy_t.get_ctype()),
	("track_client_session", ct.c_int),
	("idle_timeout_secs", ct.c_uint),
	]

coap_proxy_response_handler_t = ct.CFUNCTYPE(ct.c_void_p, ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.POINTER(coap_pdu_t), ct.POINTER(coap_cache_key_t))
class coap_memory_tag_t(ctypes_enum_gen):
	COAP_STRING = 0
	COAP_ATTRIBUTE_NAME = 1
	COAP_ATTRIBUTE_VALUE = 2
	COAP_PACKET = 3
	COAP_NODE = 4
	COAP_CONTEXT = 5
	COAP_ENDPOINT = 6
	COAP_PDU = 7
	COAP_PDU_BUF = 8
	COAP_RESOURCE = 9
	COAP_RESOURCEATTR = 10
	COAP_DTLS_SESSION = 11
	COAP_SESSION = 12
	COAP_OPTLIST = 13
	COAP_CACHE_KEY = 14
	COAP_CACHE_ENTRY = 15
	COAP_LG_XMIT = 16
	COAP_LG_CRCV = 17
	COAP_LG_SRCV = 18
	COAP_DIGEST_CTX = 19
	COAP_SUBSCRIPTION = 20
	COAP_DTLS_CONTEXT = 21
	COAP_OSCORE_COM = 22
	COAP_OSCORE_SEN = 23
	COAP_OSCORE_REC = 24
	COAP_OSCORE_EX = 25
	COAP_OSCORE_EP = 26
	COAP_OSCORE_BUF = 27
	COAP_COSE = 28
	COAP_MEM_TAG_LAST = 29

coap_rand_func_t = ct.CFUNCTYPE(ct.c_int, ct.py_object, ct.c_ulong)
coap_method_handler_t = ct.CFUNCTYPE(None, ct.POINTER(coap_resource_t), ct.POINTER(coap_session_t), ct.POINTER(coap_pdu_t), ct.POINTER(coap_string_t), ct.POINTER(coap_pdu_t))
coap_resource_release_userdata_handler_t = ct.CFUNCTYPE(None, ct.py_object)
coap_print_status_t = ct.c_uint
coap_observe_added_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_session_t), ct.POINTER(coap_subscription_t), coap_proto_t.get_ctype(), ct.POINTER(coap_address_t), ct.POINTER(coap_addr_tuple_t), ct.POINTER(coap_bin_const_t), ct.POINTER(coap_bin_const_t), ct.py_object)
coap_observe_deleted_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_session_t), ct.POINTER(coap_subscription_t), ct.py_object)
coap_track_observe_value_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_context_t), ct.POINTER(coap_str_const_t), ct.c_uint, ct.py_object)
coap_dyn_resource_added_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_session_t), ct.POINTER(coap_str_const_t), ct.POINTER(coap_bin_const_t), ct.py_object)
coap_resource_deleted_t = ct.CFUNCTYPE(ct.c_int, ct.POINTER(coap_context_t), ct.POINTER(coap_str_const_t), ct.py_object)
library_functions.append({
	"name": "coap_startup",
	"restype": None,
	})
library_functions.append({
	"name": "coap_cleanup",
	"restype": None,
	})
library_functions.append({
	"name": "coap_opt_parse",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		(ct.c_size_t, "length"),
		(ct.POINTER(coap_option_t), "result"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_opt_size",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_option_filter_clear",
	"args": [
		(ct.POINTER(coap_opt_filter_t), "filter"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_option_filter_set",
	"args": [
		(ct.POINTER(coap_opt_filter_t), "filter"),
		(ct.c_ushort, "number"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_option_filter_unset",
	"args": [
		(ct.POINTER(coap_opt_filter_t), "filter"),
		(ct.c_ushort, "number"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_option_filter_get",
	"args": [
		(ct.POINTER(coap_opt_filter_t), "filter"),
		(ct.c_ushort, "number"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_option_iterator_init",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.POINTER(coap_opt_iterator_t), "oi"),
		(ct.POINTER(coap_opt_filter_t), "filter"),
		],
	"restype": ct.POINTER(coap_opt_iterator_t),
	})
library_functions.append({
	"name": "coap_option_next",
	"args": [
		(ct.POINTER(coap_opt_iterator_t), "oi"),
		],
	"restype": ct.POINTER(ct.c_uint8),
	})
library_functions.append({
	"name": "coap_check_option",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_ushort, "number"),
		(ct.POINTER(coap_opt_iterator_t), "oi"),
		],
	"restype": ct.POINTER(ct.c_uint8),
	})
library_functions.append({
	"name": "coap_opt_setheader",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		(ct.c_size_t, "maxlen"),
		(ct.c_ushort, "delta"),
		(ct.c_size_t, "length"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_opt_encode_size",
	"args": [
		(ct.c_ushort, "delta"),
		(ct.c_size_t, "length"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_opt_encode",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		(ct.c_size_t, "n"),
		(ct.c_ushort, "delta"),
		(ct.POINTER(ct.c_uint8), "val"),
		(ct.c_size_t, "length"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_opt_length",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_opt_value",
	"args": [
		(ct.POINTER(ct.c_uint8), "opt"),
		],
	"restype": ct.POINTER(ct.c_uint8),
	})
library_functions.append({
	"name": "coap_new_optlist",
	"args": [
		(ct.c_ushort, "number"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "data"),
		],
	"restype": ct.POINTER(coap_optlist_t),
	})
library_functions.append({
	"name": "coap_add_optlist_pdu",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_insert_optlist",
	"args": [
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		(ct.POINTER(coap_optlist_t), "optlist"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_delete_optlist",
	"args": [
		(ct.POINTER(coap_optlist_t), "optlist_chain"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_new_string",
	"args": [
		(ct.c_size_t, "size"),
		],
	"restype": ct.POINTER(coap_string_t),
	})
library_functions.append({
	"name": "coap_delete_string",
	"args": [
		(ct.POINTER(coap_string_t), "string"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_new_str_const",
	"args": [
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.POINTER(coap_str_const_t),
	})
library_functions.append({
	"name": "coap_delete_str_const",
	"args": [
		(ct.POINTER(coap_str_const_t), "string"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_new_binary",
	"args": [
		(ct.c_size_t, "size"),
		],
	"restype": ct.POINTER(coap_binary_t),
	})
library_functions.append({
	"name": "coap_delete_binary",
	"args": [
		(ct.POINTER(coap_binary_t), "binary"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_resize_binary",
	"args": [
		(ct.POINTER(coap_binary_t), "binary"),
		(ct.c_size_t, "new_size"),
		],
	"restype": ct.POINTER(coap_binary_t),
	})
library_functions.append({
	"name": "coap_new_bin_const",
	"args": [
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.POINTER(coap_bin_const_t),
	})
library_functions.append({
	"name": "coap_delete_bin_const",
	"args": [
		(ct.POINTER(coap_bin_const_t), "binary"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_make_str_const",
	"args": [
		(ct.c_char_p, "string"),
		],
	"restype": ct.POINTER(coap_str_const_t),
	})
library_functions.append({
	"name": "coap_host_is_unix_domain",
	"args": [
		(ct.POINTER(coap_str_const_t), "host"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_new_uri",
	"args": [
		(ct.POINTER(ct.c_uint8), "uri"),
		(ct.c_uint, "length"),
		],
	"restype": ct.POINTER(coap_uri_t),
	})
library_functions.append({
	"name": "coap_clone_uri",
	"args": [
		(ct.POINTER(coap_uri_t), "uri"),
		],
	"restype": ct.POINTER(coap_uri_t),
	})
library_functions.append({
	"name": "coap_delete_uri",
	"args": [
		(ct.POINTER(coap_uri_t), "uri"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_split_uri",
	"args": [
		(ct.POINTER(ct.c_uint8), "str_var"),
		(ct.c_size_t, "len"),
		(ct.POINTER(coap_uri_t), "uri"),
		],
	"restype": ct.c_int,
	"expect": 0,
	})
library_functions.append({
	"name": "coap_split_proxy_uri",
	"args": [
		(ct.POINTER(ct.c_uint8), "str_var"),
		(ct.c_size_t, "len"),
		(ct.POINTER(coap_uri_t), "uri"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_uri_into_options",
	"args": [
		(ct.POINTER(coap_uri_t), "uri"),
		(ct.POINTER(coap_address_t), "dst"),
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		(ct.c_int, "create_port_host_opt"),
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.c_size_t, "buflen"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_uri_into_optlist",
	"args": [
		(ct.POINTER(coap_uri_t), "uri"),
		(ct.POINTER(coap_address_t), "dst"),
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		(ct.c_int, "create_port_host_opt"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_split_path",
	"args": [
		(ct.POINTER(ct.c_uint8), "path"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.POINTER(ct.c_size_t), "buflen"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_path_into_optlist",
	"args": [
		(ct.POINTER(ct.c_uint8), "path"),
		(ct.c_size_t, "length"),
		(ct.c_ushort, "optnum"),
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_split_query",
	"args": [
		(ct.POINTER(ct.c_uint8), "query"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.POINTER(ct.c_size_t), "buflen"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_query_into_optlist",
	"args": [
		(ct.POINTER(ct.c_uint8), "query"),
		(ct.c_size_t, "length"),
		(ct.c_ushort, "optnum"),
		(ct.POINTER(ct.POINTER(coap_optlist_t)), "optlist_chain"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_get_query",
	"args": [
		(ct.POINTER(coap_pdu_t), "request"),
		],
	"restype": ct.POINTER(coap_string_t),
	})
library_functions.append({
	"name": "coap_get_uri_path",
	"args": [
		(ct.POINTER(coap_pdu_t), "request"),
		],
	"restype": ct.POINTER(coap_string_t),
	})
library_functions.append({
	"name": "coap_response_phrase",
	"args": [
		(ct.c_uint8, "code"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_pdu_init",
	"args": [
		(coap_pdu_type_t.get_ctype(), "type"),
		(coap_pdu_code_t.get_ctype(), "code"),
		(ct.c_int, "mid"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.POINTER(coap_pdu_t),
	})
library_functions.append({
	"name": "coap_new_pdu",
	"args": [
		(coap_pdu_type_t.get_ctype(), "type"),
		(coap_pdu_code_t.get_ctype(), "code"),
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_pdu_t),
	})
library_functions.append({
	"name": "coap_delete_pdu",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_pdu_duplicate",
	"args": [
		(ct.POINTER(coap_pdu_t), "old_pdu"),
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_size_t, "token_length"),
		(ct.POINTER(ct.c_uint8), "token"),
		(ct.POINTER(coap_opt_filter_t), "drop_options"),
		],
	"restype": ct.POINTER(coap_pdu_t),
	})
library_functions.append({
	"name": "coap_pdu_parse",
	"args": [
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.c_size_t, "length"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_token",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "len"),
		(ct.POINTER(ct.c_uint8), "data"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_option",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_ushort, "number"),
		(ct.c_size_t, "len"),
		(ct.POINTER(ct.c_uint8), "data"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_add_data",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "len"),
		(ct.POINTER(ct.c_uint8), "data"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_data_after",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "len"),
		],
	"restype": ct.POINTER(ct.c_uint8),
	})
library_functions.append({
	"name": "coap_get_data",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.POINTER(ct.c_size_t), "len"),
		(ct.POINTER(ct.POINTER(ct.c_uint8)), "data"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_get_data_large",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.POINTER(ct.c_size_t), "len"),
		(ct.POINTER(ct.POINTER(ct.c_uint8)), "data"),
		(ct.POINTER(ct.c_size_t), "offset"),
		(ct.POINTER(ct.c_size_t), "total"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_pdu_get_code",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": coap_pdu_code_t.get_ctype(),
	"llapi_check": False,
	})
library_functions.append({
	"name": "coap_pdu_set_code",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_pdu_code_t.get_ctype(), "code"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_pdu_get_type",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": coap_pdu_type_t.get_ctype(),
	"llapi_check": False,
	})
library_functions.append({
	"name": "coap_pdu_set_type",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_pdu_type_t.get_ctype(), "type"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_pdu_get_token",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": coap_bin_const_t,
	})
library_functions.append({
	"name": "coap_pdu_get_mid",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_pdu_set_mid",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_int, "mid"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_address_get_port",
	"args": [
		(ct.POINTER(coap_address_t), "addr"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_address_set_port",
	"args": [
		(ct.POINTER(coap_address_t), "addr"),
		(ct.c_ushort, "port"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_address_equals",
	"args": [
		(ct.POINTER(coap_address_t), "a"),
		(ct.POINTER(coap_address_t), "b"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "_coap_address_isany_impl",
	"args": [
		(ct.POINTER(coap_address_t), "a"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_get_available_scheme_hint_bits",
	"args": [
		(ct.c_int, "have_pki_psk"),
		(ct.c_int, "ws_check"),
		(coap_proto_t.get_ctype(), "use_unix_proto"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_resolve_address_info",
	"args": [
		(ct.POINTER(coap_str_const_t), "address"),
		(ct.c_ushort, "port"),
		(ct.c_ushort, "secure_port"),
		(ct.c_ushort, "ws_port"),
		(ct.c_ushort, "ws_secure_port"),
		(ct.c_int, "ai_hints_flags"),
		(ct.c_int, "scheme_hint_bits"),
		(coap_resolve_type_t.get_ctype(), "type"),
		],
	"restype": ct.POINTER(coap_addr_info_t),
	})
library_functions.append({
	"name": "coap_free_address_info",
	"args": [
		(ct.POINTER(coap_addr_info_t), "info_list"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_address_init",
	"args": [
		(ct.POINTER(coap_address_t), "addr"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_address_set_unix_domain",
	"args": [
		(ct.POINTER(coap_address_t), "addr"),
		(ct.POINTER(ct.c_uint8), "host"),
		(ct.c_size_t, "host_len"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_address_copy",
	"args": [
		(ct.POINTER(coap_address_t), "dst"),
		(ct.POINTER(coap_address_t), "src"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_is_mcast",
	"args": [
		(ct.POINTER(coap_address_t), "a"),
		],
	"restype": ct.c_int,
	"llapi_check": False,
	})
library_functions.append({
	"name": "coap_is_bcast",
	"args": [
		(ct.POINTER(coap_address_t), "a"),
		],
	"restype": ct.c_int,
	"llapi_check": False,
	})
library_functions.append({
	"name": "coap_is_af_unix",
	"args": [
		(ct.POINTER(coap_address_t), "a"),
		],
	"restype": ct.c_int,
	"llapi_check": False,
	})
library_functions.append({
	"name": "coap_socket_strerror",
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_clock_init",
	"restype": None,
	})
library_functions.append({
	"name": "coap_ticks",
	"args": [
		(ct.POINTER(ct.c_ulong), "t"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_ticks_to_rt",
	"args": [
		(ct.c_ulong, "t"),
		],
	"restype": ct.c_long,
	})
library_functions.append({
	"name": "coap_ticks_to_rt_us",
	"args": [
		(ct.c_ulong, "t"),
		],
	"restype": ct.c_ulong,
	})
library_functions.append({
	"name": "coap_ticks_from_rt_us",
	"args": [
		(ct.c_ulong, "t"),
		],
	"restype": ct.c_ulong,
	})
library_functions.append({
	"name": "coap_tls_engine_configure",
	"args": [
		(ct.POINTER(coap_str_const_t), "conf_mem"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_tls_engine_remove",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_get_tls_library_version",
	"restype": ct.POINTER(coap_tls_version_t),
	})
library_functions.append({
	"name": "coap_register_event_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_event_handler_t, "hnd"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_set_event_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_event_handler_t, "hnd"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_clear_event_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_reference",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_session_release",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_disconnected",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_nack_reason_t.get_ctype(), "reason"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_set_app_data",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.py_object, "data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_app_data",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_session_set_app_data2",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_session_get_addr_remote",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_address_t),
	})
library_functions.append({
	"name": "coap_session_get_addr_mcast",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_address_t),
	})
library_functions.append({
	"name": "coap_session_get_addr_local",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_address_t),
	})
library_functions.append({
	"name": "coap_session_get_proto",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_proto_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_session_get_type",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_session_type_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_session_get_state",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_session_state_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_session_get_endpoint",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_endpoint_t),
	})
library_functions.append({
	"name": "coap_session_get_ifindex",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_session_get_tls",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_tls_library_t.get_ctype()), "tls_lib"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_session_get_context",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_context_t),
	})
library_functions.append({
	"name": "coap_session_set_type_client",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_session_set_type_server",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_session_set_mtu",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_uint, "mtu"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_max_pdu_size",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_new_client_session",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_new_client_session_psk",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.c_char_p, "identity"),
		(ct.POINTER(ct.c_uint8), "key"),
		(ct.c_uint, "key_len"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_new_client_session_psk2",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(coap_dtls_cpsk_t), "setup_data"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_session_get_psk_hint",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_bin_const_t),
	})
library_functions.append({
	"name": "coap_session_get_psk_identity",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_bin_const_t),
	})
library_functions.append({
	"name": "coap_session_get_psk_key",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.POINTER(coap_bin_const_t),
	})
library_functions.append({
	"name": "coap_new_client_session_pki",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(coap_dtls_pki_t), "setup_data"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_session_init_token",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "token"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_new_token",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(ct.c_size_t), "length"),
		(ct.POINTER(ct.c_uint8), "token"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_str",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_new_endpoint",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_address_t), "listen_addr"),
		(coap_proto_t.get_ctype(), "proto"),
		],
	"restype": ct.POINTER(coap_endpoint_t),
	})
library_functions.append({
	"name": "coap_endpoint_set_default_mtu",
	"args": [
		(ct.POINTER(coap_endpoint_t), "endpoint"),
		(ct.c_uint, "mtu"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_free_endpoint",
	"args": [
		(ct.POINTER(coap_endpoint_t), "endpoint"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_endpoint_get_app_data",
	"args": [
		(ct.POINTER(coap_endpoint_t), "endpoint"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_endpoint_set_app_data",
	"args": [
		(ct.POINTER(coap_endpoint_t), "endpoint"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_session_get_by_peer",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_address_t), "remote_addr"),
		(ct.c_int, "ifindex"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_endpoint_str",
	"args": [
		(ct.POINTER(coap_endpoint_t), "endpoint"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_session_set_ack_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_fixed_point_t, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_ack_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_fixed_point_t,
	})
library_functions.append({
	"name": "coap_session_set_ack_random_factor",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_fixed_point_t, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_ack_random_factor",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_fixed_point_t,
	})
library_functions.append({
	"name": "coap_session_set_max_retransmit",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_ushort, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_max_retransmit",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_session_set_nstart",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_ushort, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_nstart",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_session_set_default_leisure",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_fixed_point_t, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_default_leisure",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_fixed_point_t,
	})
library_functions.append({
	"name": "coap_session_set_probing_rate",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_uint, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_probing_rate",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_session_set_max_payloads",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_ushort, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_max_payloads",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_session_set_non_max_retransmit",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_ushort, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_non_max_retransmit",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_session_set_non_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_fixed_point_t, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_non_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_fixed_point_t,
	})
library_functions.append({
	"name": "coap_session_set_non_receive_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_fixed_point_t, "value"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_session_get_non_receive_timeout",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": coap_fixed_point_t,
	})
library_functions.append({
	"name": "coap_session_send_ping",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_session_set_no_observe_cancel",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_get_log_level",
	"restype": coap_log_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_set_log_level",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_dtls_set_log_level",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_dtls_get_log_level",
	"restype": coap_log_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_log_level_desc",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_set_log_handler",
	"args": [
		(coap_log_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_package_name",
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_package_version",
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_package_build",
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_log_impl",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		(ct.c_char_p, "format"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_set_show_pdu_output",
	"args": [
		(ct.c_int, "use_fprintf"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_enable_pdu_data_output",
	"args": [
		(ct.c_int, "enable_data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_show_pdu",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_show_tls_version",
	"args": [
		(coap_log_t.get_ctype(), "level"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_string_tls_version",
	"args": [
		(ct.c_char_p, "buffer"),
		(ct.c_size_t, "bufsize"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_string_tls_support",
	"args": [
		(ct.c_char_p, "buffer"),
		(ct.c_size_t, "bufsize"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_print_addr",
	"args": [
		(ct.POINTER(coap_address_t), "address"),
		(ct.POINTER(ct.c_uint8), "buffer"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.c_size_t,
	})
library_functions.append({
	"name": "coap_print_ip_addr",
	"args": [
		(ct.POINTER(coap_address_t), "address"),
		(ct.c_char_p, "buffer"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.c_char_p,
	})
library_functions.append({
	"name": "coap_debug_set_packet_loss",
	"args": [
		(ct.c_char_p, "loss_level"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_register_response_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_response_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_nack_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_nack_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_ping_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_ping_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_pong_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_pong_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_dynamic_resource_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_resource_dynamic_create_t, "create_handler"),
		(ct.c_uint, "dynamic_max"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_option",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_ushort, "number"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_new_context",
	"args": [
		(ct.POINTER(coap_address_t), "listen_addr"),
		],
	"restype": ct.POINTER(coap_context_t),
	})
library_functions.append({
	"name": "coap_context_set_psk",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_char_p, "hint"),
		(ct.POINTER(ct.c_uint8), "key"),
		(ct.c_size_t, "key_len"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_psk2",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_dtls_spsk_t), "setup_data"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_pki",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_dtls_pki_t), "setup_data"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_pki_root_cas",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_char_p, "ca_file"),
		(ct.c_char_p, "ca_dir"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_load_pki_trust_store",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_keepalive",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "seconds"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_cid_tuple_change",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint8, "every"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_max_token_size",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_size_t, "max_token_size"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_coap_fd",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_int,
	"res_error": -1,
	})
library_functions.append({
	"name": "coap_context_set_max_idle_sessions",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "max_idle_sessions"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_max_idle_sessions",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_context_set_session_timeout",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "session_timeout"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_session_reconnect_time",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "reconnect_time"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_session_timeout",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_context_set_shutdown_no_observe",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_csm_timeout",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "csm_timeout"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_csm_timeout",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_context_set_csm_timeout_ms",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "csm_timeout_ms"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_csm_timeout_ms",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_context_set_csm_max_message_size",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "csm_max_message_size"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_csm_max_message_size",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_context_set_max_handshake_sessions",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "max_handshake_sessions"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_get_max_handshake_sessions",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_new_message_id",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_free_context",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_set_app_data",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.py_object, "data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_get_app_data",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_new_error_response",
	"args": [
		(ct.POINTER(coap_pdu_t), "request"),
		(coap_pdu_code_t.get_ctype(), "code"),
		(ct.POINTER(coap_opt_filter_t), "opts"),
		],
	"restype": ct.POINTER(coap_pdu_t),
	})
library_functions.append({
	"name": "coap_send_error",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		(coap_pdu_code_t.get_ctype(), "code"),
		(ct.POINTER(coap_opt_filter_t), "opts"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_send_message_type",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		(coap_pdu_type_t.get_ctype(), "type"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_send_ack",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_send_rst",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_send",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		],
	"restype": ct.c_int,
	"res_error": COAP_INVALID_MID,
	})
library_functions.append({
	"name": "coap_send_recv",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request_pdu"),
		(ct.POINTER(ct.POINTER(coap_pdu_t)), "response_pdu"),
		(ct.c_uint, "timeout_ms"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_send_recv_terminate",
	"restype": None,
	})
library_functions.append({
	"name": "coap_handle_event",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_event_t.get_ctype(), "event"),
		(ct.POINTER(coap_session_t), "session"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_can_exit",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_join_mcast_group_intf",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.c_char_p, "groupname"),
		(ct.c_char_p, "ifname"),
		],
	"restype": ct.c_int,
	"res_error": -1,
	})
library_functions.append({
	"name": "coap_mcast_set_hops",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.c_size_t, "hops"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_mcast_per_resource",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_app_data",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.py_object, "data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_app_data2",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_context_get_app_data",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_io_process",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.c_uint, "timeout_ms"),
		],
	"restype": ct.c_int,
	"res_error": -1,
	})
library_functions.append({
	"name": "coap_io_process_with_fds",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.c_uint, "timeout_ms"),
		(ct.c_int, "nfds"),
		(ct.POINTER(fd_set), "readfds"),
		(ct.POINTER(fd_set), "writefds"),
		(ct.POINTER(fd_set), "exceptfds"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_io_pending",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_io_prepare_io",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(ct.POINTER(coap_socket_t)), "sockets"),
		(ct.c_uint, "max_sockets"),
		(ct.POINTER(ct.c_uint), "num_sockets"),
		(ct.c_ulong, "now"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_io_do_io",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.c_ulong, "now"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_io_prepare_epoll",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.c_ulong, "now"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_io_do_epoll",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(epoll_event), "events"),
		(ct.c_size_t, "nevents"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_io_process_loop",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_io_process_thread_t, "main_loop_code"),
		(ct.py_object, "main_loop_code_arg"),
		(ct.c_uint, "timeout_ms"),
		(ct.c_uint, "thread_count"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_io_process_terminate_loop",
	"restype": None,
	})
library_functions.append({
	"name": "coap_io_process_configure_threads",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "thread_count"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_io_process_remove_threads",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_socket_get_fd",
	"args": [
		(ct.POINTER(coap_socket_t), "socket"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_io_get_fds",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(ct.c_int), "read_fds"),
		(ct.POINTER(ct.c_uint), "have_read_fds"),
		(ct.c_uint, "max_read_fds"),
		(ct.POINTER(ct.c_int), "write_fds"),
		(ct.POINTER(ct.c_uint), "have_write_fds"),
		(ct.c_uint, "max_write_fds"),
		(ct.POINTER(ct.c_uint), "rem_timeout_ms"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_socket_get_flags",
	"args": [
		(ct.POINTER(coap_socket_t), "socket"),
		],
	"restype": ct.c_ushort,
	})
library_functions.append({
	"name": "coap_socket_set_flags",
	"args": [
		(ct.POINTER(coap_socket_t), "socket"),
		(ct.c_ushort, "flags"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_async",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		(ct.c_ulong, "delay"),
		],
	"restype": ct.POINTER(coap_async_t),
	})
library_functions.append({
	"name": "coap_async_set_delay",
	"args": [
		(ct.POINTER(coap_async_t), "async"),
		(ct.c_ulong, "delay"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_async_trigger",
	"args": [
		(ct.POINTER(coap_async_t), "async"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_free_async",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_async_t), "async"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_find_async",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(coap_bin_const_t, "token"),
		],
	"restype": ct.POINTER(coap_async_t),
	})
library_functions.append({
	"name": "coap_async_set_app_data",
	"args": [
		(ct.POINTER(coap_async_t), "async"),
		(ct.py_object, "app_data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_async_get_app_data",
	"args": [
		(ct.POINTER(coap_async_t), "async"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_async_set_app_data2",
	"args": [
		(ct.POINTER(coap_async_t), "async_entry"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_fls",
	"args": [
		(ct.c_uint, "i"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_flsll",
	"args": [
		(ct.c_longlong, "i"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_decode_var_bytes",
	"args": [
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.c_size_t, "length"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_decode_var_bytes8",
	"args": [
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.c_size_t, "length"),
		],
	"restype": ct.c_ulong,
	})
library_functions.append({
	"name": "coap_encode_var_safe",
	"args": [
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.c_size_t, "length"),
		(ct.c_uint, "value"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_encode_var_safe8",
	"args": [
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.c_size_t, "length"),
		(ct.c_ulong, "value"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_opt_block_num",
	"args": [
		(ct.POINTER(ct.c_uint8), "block_opt"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_get_block",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_ushort, "number"),
		(ct.POINTER(coap_block_t), "block"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_get_block_b",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_ushort, "number"),
		(ct.POINTER(coap_block_b_t), "block"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_write_block_opt",
	"args": [
		(ct.POINTER(coap_block_t), "block"),
		(ct.c_ushort, "number"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "data_length"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_write_block_b_opt",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_block_b_t), "block"),
		(ct.c_ushort, "number"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "data_length"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_block",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "len"),
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.c_uint, "block_num"),
		(ct.c_uint8, "block_szx"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_block_b_data",
	"args": [
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "len"),
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.POINTER(coap_block_b_t), "block"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_block_build_body",
	"args": [
		(ct.POINTER(coap_binary_t), "body_data"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "data"),
		(ct.c_size_t, "offset"),
		(ct.c_size_t, "total"),
		],
	"restype": ct.POINTER(coap_binary_t),
	})
library_functions.append({
	"name": "coap_add_data_blocked_response",
	"args": [
		(ct.POINTER(coap_pdu_t), "request"),
		(ct.POINTER(coap_pdu_t), "response"),
		(ct.c_ushort, "media_type"),
		(ct.c_int, "maxage"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_add_data_large_request",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "data"),
		(coap_release_large_data_t, "release_func"),
		(ct.py_object, "app_ptr"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_add_data_large_response",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "request"),
		(ct.POINTER(coap_pdu_t), "response"),
		(ct.POINTER(coap_string_t), "query"),
		(ct.c_ushort, "media_type"),
		(ct.c_int, "maxage"),
		(ct.c_ulong, "etag"),
		(ct.c_size_t, "length"),
		(ct.POINTER(ct.c_uint8), "data"),
		(coap_release_large_data_t, "release_func"),
		(ct.py_object, "app_ptr"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_context_set_block_mode",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_uint, "block_mode"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_context_set_max_block_size",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_size_t, "max_block_size"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_cache_derive_key",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_cache_session_based_t.get_ctype(), "session_based"),
		],
	"restype": ct.POINTER(coap_cache_key_t),
	})
library_functions.append({
	"name": "coap_cache_derive_key_w_ignore",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_cache_session_based_t.get_ctype(), "session_based"),
		(ct.POINTER(ct.c_ushort), "ignore_options"),
		(ct.c_size_t, "ignore_count"),
		],
	"restype": ct.POINTER(coap_cache_key_t),
	})
library_functions.append({
	"name": "coap_delete_cache_key",
	"args": [
		(ct.POINTER(coap_cache_key_t), "cache_key"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_cache_ignore_options",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(ct.c_ushort), "options"),
		(ct.c_size_t, "count"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_new_cache_entry",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_cache_record_pdu_t.get_ctype(), "record_pdu"),
		(coap_cache_session_based_t.get_ctype(), "session_based"),
		(ct.c_uint, "idle_time"),
		],
	"restype": ct.POINTER(coap_cache_entry_t),
	})
library_functions.append({
	"name": "coap_delete_cache_entry",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_cache_entry_t), "cache_entry"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_cache_get_by_key",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_cache_key_t), "cache_key"),
		],
	"restype": ct.POINTER(coap_cache_entry_t),
	})
library_functions.append({
	"name": "coap_cache_get_by_pdu",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_pdu_t), "pdu"),
		(coap_cache_session_based_t.get_ctype(), "session_based"),
		],
	"restype": ct.POINTER(coap_cache_entry_t),
	})
library_functions.append({
	"name": "coap_cache_get_pdu",
	"args": [
		(ct.POINTER(coap_cache_entry_t), "cache_entry"),
		],
	"restype": ct.POINTER(coap_pdu_t),
	})
library_functions.append({
	"name": "coap_cache_set_app_data",
	"args": [
		(ct.POINTER(coap_cache_entry_t), "cache_entry"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_cache_set_app_data2",
	"args": [
		(ct.POINTER(coap_cache_entry_t), "cache_entry"),
		(ct.py_object, "data"),
		(coap_app_data_free_callback_t, "callback"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_cache_get_app_data",
	"args": [
		(ct.POINTER(coap_cache_entry_t), "cache_entry"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_new_client_session_oscore",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(coap_oscore_conf_t), "oscore_conf"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_new_client_session_oscore_psk",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(coap_dtls_cpsk_t), "psk_data"),
		(ct.POINTER(coap_oscore_conf_t), "oscore_conf"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_new_client_session_oscore_pki",
	"args": [
		(ct.POINTER(coap_context_t), "ctx"),
		(ct.POINTER(coap_address_t), "local_if"),
		(ct.POINTER(coap_address_t), "server"),
		(coap_proto_t.get_ctype(), "proto"),
		(ct.POINTER(coap_dtls_pki_t), "pki_data"),
		(ct.POINTER(coap_oscore_conf_t), "oscore_conf"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_context_oscore_server",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_oscore_conf_t), "oscore_conf"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_new_oscore_conf",
	"args": [
		(coap_str_const_t, "conf_mem"),
		(coap_oscore_save_seq_num_t, "save_seq_num_func"),
		(ct.py_object, "save_seq_num_func_param"),
		(ct.c_ulong, "start_seq_num"),
		],
	"restype": ct.POINTER(coap_oscore_conf_t),
	})
library_functions.append({
	"name": "coap_delete_oscore_conf",
	"args": [
		(ct.POINTER(coap_oscore_conf_t), "oscore_conf"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_new_oscore_recipient",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_bin_const_t), "recipient_id"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_delete_oscore_recipient",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_bin_const_t), "recipient_id"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_register_proxy_response_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_proxy_response_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_verify_proxy_scheme_supported",
	"args": [
		(coap_uri_scheme_t.get_ctype(), "scheme"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_proxy_forward_request",
	"args": [
		(ct.POINTER(coap_session_t), "req_session"),
		(ct.POINTER(coap_pdu_t), "request"),
		(ct.POINTER(coap_pdu_t), "response"),
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(coap_cache_key_t), "cache_key"),
		(ct.POINTER(coap_proxy_server_list_t), "server_list"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_proxy_forward_response",
	"args": [
		(ct.POINTER(coap_session_t), "rsp_session"),
		(ct.POINTER(coap_pdu_t), "received"),
		(ct.POINTER(ct.POINTER(coap_cache_key_t)), "cache_key"),
		],
	"restype": coap_response_t.get_ctype(),
	})
library_functions.append({
	"name": "coap_new_client_session_proxy",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_proxy_server_list_t), "server_list"),
		],
	"restype": ct.POINTER(coap_session_t),
	})
library_functions.append({
	"name": "coap_memory_init",
	"restype": None,
	})
library_functions.append({
	"name": "coap_malloc_type",
	"args": [
		(coap_memory_tag_t.get_ctype(), "type"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_realloc_type",
	"args": [
		(coap_memory_tag_t.get_ctype(), "type"),
		(ct.py_object, "p"),
		(ct.c_size_t, "size"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_free_type",
	"args": [
		(coap_memory_tag_t.get_ctype(), "type"),
		(ct.py_object, "p"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_dump_memory_type_counts",
	"args": [
		(coap_log_t.get_ctype(), "log_level"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_set_prng",
	"args": [
		(coap_rand_func_t, "rng"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_prng_init",
	"args": [
		(ct.c_uint, "seed"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_prng",
	"args": [
		(ct.py_object, "buf"),
		(ct.c_size_t, "len"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_resource_init",
	"args": [
		(ct.POINTER(coap_str_const_t), "uri_path"),
		(ct.c_int, "flags"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_unknown_init",
	"args": [
		(coap_method_handler_t, "put_handler"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_unknown_init2",
	"args": [
		(coap_method_handler_t, "put_handler"),
		(ct.c_int, "flags"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_proxy_uri_init",
	"args": [
		(coap_method_handler_t, "handler"),
		(ct.c_size_t, "host_name_count"),
		(ct.POINTER(ct.c_char_p), "host_name_list"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_proxy_uri_init2",
	"args": [
		(coap_method_handler_t, "handler"),
		(ct.c_size_t, "host_name_count"),
		(ct.POINTER(ct.c_char_p), "host_name_list"),
		(ct.c_int, "flags"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_reverse_proxy_init",
	"args": [
		(coap_method_handler_t, "handler"),
		(ct.c_int, "flags"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_get_resource_from_uri_path",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_str_const_t), "uri_path"),
		],
	"restype": ct.POINTER(coap_resource_t),
	})
library_functions.append({
	"name": "coap_resource_get_uri_path",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		],
	"restype": ct.POINTER(coap_str_const_t),
	})
library_functions.append({
	"name": "coap_resource_set_mode",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.c_int, "mode"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_resource_set_userdata",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.py_object, "data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_resource_get_userdata",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		],
	"restype": ct.py_object,
	})
library_functions.append({
	"name": "coap_resource_release_userdata_handler",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_resource_release_userdata_handler_t, "callback"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_add_resource",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_resource_t), "resource"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_delete_resource",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(coap_resource_t), "resource"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_register_handler",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(coap_request_t.get_ctype(), "method"),
		(coap_method_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_register_request_handler",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(coap_request_t.get_ctype(), "method"),
		(coap_method_handler_t, "handler"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_add_attr",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(coap_str_const_t), "name"),
		(ct.POINTER(coap_str_const_t), "value"),
		(ct.c_int, "flags"),
		],
	"restype": ct.POINTER(coap_attr_t),
	})
library_functions.append({
	"name": "coap_find_attr",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(coap_str_const_t), "name"),
		],
	"restype": ct.POINTER(coap_attr_t),
	})
library_functions.append({
	"name": "coap_attr_get_value",
	"args": [
		(ct.POINTER(coap_attr_t), "attribute"),
		],
	"restype": ct.POINTER(coap_str_const_t),
	})
library_functions.append({
	"name": "coap_print_link",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.POINTER(ct.c_size_t), "len"),
		(ct.POINTER(ct.c_size_t), "offset"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_print_wellknown",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.POINTER(ct.c_uint8), "buf"),
		(ct.POINTER(ct.c_size_t), "buflen"),
		(ct.c_size_t, "offset"),
		(ct.POINTER(coap_string_t), "query_filter"),
		],
	"restype": ct.c_uint,
	})
library_functions.append({
	"name": "coap_resource_set_dirty",
	"args": [
		(ct.POINTER(coap_resource_t), "r"),
		(ct.POINTER(coap_string_t), "query"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_resource_set_get_observable",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.c_int, "mode"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_resource_notify_observers",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.POINTER(coap_string_t), "query"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_check_notify",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_persist_track_funcs",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_observe_added_t, "observe_added"),
		(coap_observe_deleted_t, "observe_deleted"),
		(coap_track_observe_value_t, "track_observe_value"),
		(coap_dyn_resource_added_t, "dyn_resource_added"),
		(coap_resource_deleted_t, "resource_deleted"),
		(ct.c_uint, "save_freq"),
		(ct.py_object, "user_data"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_persist_observe_add",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(coap_proto_t.get_ctype(), "e_proto"),
		(ct.POINTER(coap_address_t), "e_listen_addr"),
		(ct.POINTER(coap_addr_tuple_t), "s_addr_info"),
		(ct.POINTER(coap_bin_const_t), "raw_packet"),
		(ct.POINTER(coap_bin_const_t), "oscore_info"),
		],
	"restype": ct.POINTER(coap_subscription_t),
	})
library_functions.append({
	"name": "coap_persist_startup",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		(ct.c_char_p, "dyn_resource_save_file"),
		(ct.c_char_p, "observe_save_file"),
		(ct.c_char_p, "obs_cnt_save_file"),
		(ct.c_uint, "save_freq"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_persist_stop",
	"args": [
		(ct.POINTER(coap_context_t), "context"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_persist_set_observe_num",
	"args": [
		(ct.POINTER(coap_resource_t), "resource"),
		(ct.c_uint, "observe_num"),
		],
	"restype": None,
	})
library_functions.append({
	"name": "coap_cancel_observe",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_binary_t), "token"),
		(coap_pdu_type_t.get_ctype(), "message_type"),
		],
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_af_unix_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_async_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_client_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_cid_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_psk_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_pki_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_pkcs11_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_dtls_rpk_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_epoll_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_ipv4_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_ipv6_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_observe_persist_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_oscore_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_proxy_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_q_block_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_server_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_tcp_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_threadsafe_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_tls_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_ws_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_wss_is_supported",
	"restype": ct.c_int,
	})
library_functions.append({
	"name": "coap_ws_set_host_request",
	"args": [
		(ct.POINTER(coap_session_t), "session"),
		(ct.POINTER(coap_str_const_t), "ws_host"),
		],
	"restype": ct.c_int,
	})
# from 07-default-retval.py


for fct in library_functions:
	if (
		"restype" in fct
		and fct["restype"] == ct.c_int
		and "res_error" not in fct
		and "expect" not in fct
		and fct.get("llapi_check", True) is True
		):
		fct["res_error"] = 0


# from 8-footer.py


verbosity = 0

if sys.version_info < (3,):
	def to_bytes(x):
		return x
else:
	def to_bytes(s):
		if isinstance(s, str):
			return s.encode()
		else:
			return s

def setup_fct(fdict):
	ct_fct = getattr(clibrary, fdict["name"])
	
	if "args" in fdict:
		args = []
		for arg in fdict["args"]:
			if isinstance(arg, tuple):
				if isinstance(arg[0], str):
					args.append(arg[1])
				else:
					args.append(arg[0])
			else:
				args.append(arg)
	else:
		args = None
	
	ct_fct.argtypes = args
	
	ct_fct.restype = fdict.get("restype", ct.c_int)
	# workaround if the function returns NULL
	if ct_fct.restype == ct.py_object:
		ct_fct.restype = ct.c_void_p
	
	fdict["ct_fct"] = ct_fct

def ct_call(fdict, *nargs, **kwargs):
	if "genbindgen_pre_ct_call_hook" in globals():
		genbindgen_pre_ct_call_hook(fdict, nargs, kwargs)
	
	if "ct_fct" not in fdict:
		setup_fct(fdict)
	
	ct_fct = fdict["ct_fct"]
	
	newargs = list()
	for i in range(len(nargs)):
		newargs += (to_bytes(nargs[i]), )
	
	if "args" in fdict and kwargs:
		for i in range(len(nargs), len(fdict["args"])):
			newargs += (None, )
		
		for key, value in kwargs.items():
			if key == "llapi_check":
				continue
			
			found = False
			i = 0
			for arg in fdict["args"]:
				if isinstance(arg, tuple):
					if isinstance(arg[0], str):
						if key == arg[0]:
							found = True
					else:
						if key == arg[1]:
							found = True
					if found:
						newargs[i] = value
						break
				i += 1
			if not found:
				raise Exception("error, argument \""+key+"\" for \""+fdict["name"]+"\" not found")
	
	if verbosity > 1:
		print(fdict["name"], newargs, end=" ")
		sys.stdout.flush()
	
	res = ct_fct(*newargs)
	if fdict.get("restype", ct.c_int) == ct.py_object:
		if res:
			res = ct.cast(res, ct.py_object).value
		else:
			res = None
	
	if verbosity > 1:
		print("=", res)
	
	if kwargs.get("llapi_check", True):
		if fdict.get("expect", False):
			if res != fdict["expect"]:
				if fdict.get("restype", ct.c_int) in [ct.c_long, ct.c_int] and res < 0:
					raise OSError(res, fdict["name"]+str(newargs)+" failed with: "+os.strerror(-res)+" ("+str(-res)+")")
				else:
					raise OSError(res, fdict["name"]+str(newargs)+" failed with: "+str(res)+" (!= "+str(fdict["expect"])+")")
		elif "res_error" in fdict:
			if res == fdict["res_error"]:
				raise OSError(res, fdict["name"]+str(newargs)+" failed with: "+str(res))
		elif fdict.get("restype", ct.c_int) in [ct.c_long, ct.c_int] and res < 0:
			raise OSError(res, fdict["name"]+str(newargs)+" failed with: "+os.strerror(-res)+" ("+str(-res)+")")
		elif isinstance(res, ct._Pointer) and not res:
			raise NullPointer(fdict["name"]+str(newargs)+" returned NULL pointer", "(errno "+str(errno())+")" if "errno" in globals() else "")
	
	return res

project_name="libcoap"

libnames = []
for version in ['', '-3']:
	for ssl_lib in ['', '-openssl', '-gnutls']:
		for tag in ['.so.3', '.so', '.dll']:
			libnames.append(f"libcoap{version}{ssl_lib}{tag}")

for env_var in ['LIBCOAP_PATH', 'LIBCOAPY_PATH', 'LIBCOAPY_LIB']:
	if os.environ.get(env_var, None):
		libnames.insert(0, os.environ.get(env_var))

clibrary = None
for libname in libnames:
	try:
		if "cdecl" == "cdecl":
			clibrary = ct.CDLL(libname)
		else:
			clibrary = ct.WinDLL(libname)
	except:
		continue
	else:
		break

if clibrary is None:
	raise Exception(f"could not find {project_name} library")

try:
	libc = None
	if os.name == "posix":
		libc = ct.CDLL('libc.so.6')
		
		libc.__errno_location.restype = ct.POINTER(ct.c_int)
		
		def errno(value=None):
			if value is None:
				return libc.__errno_location()[0]
			else:
				libc.__errno_location()[0] = value
	elif os.name == "nt":
		libc = ct.cdll.msvcrt
		
		if not libc:
			# TODO testing
			import ctypes.util as ct_util
			libname = ct_util.find_msvcrt()
			libc = ct.WinDLL(libname)
		
		libc._errno.restype = ct.POINTER(ct.c_int)
		
		def errno(value=None):
			if value is None:
				return libc._errno()[0]
			else:
				libc._set_errno(value)
	else:
		if verbosity > 0:
			print("unexpected os", os.name, file=sys.stderr)
	
	if libc:
		libc.free.args = [ct.c_void_p]
except Exception as e:
	if verbosity > 0:
		print("loading libc functions failed", str(e), file=sys.stderr)
	pass

resolve_immediately = False

for fdict in library_functions:
	if getattr(clibrary, fdict["name"], None) is None:
		if verbosity > 0:
			print(fdict["name"], "not found in library")
		continue
	
	if resolve_immediately:
		setup_fct(fdict)
	
	# we need the function generator to avoid issues due to late binding
	def function_generator(fdict=fdict):
		def dyn_fct(*nargs, **kwargs):
			return ct_call(fdict, *nargs, **kwargs)
		return dyn_fct
	
	if hasattr(locals(), fdict["name"]):
		print("duplicate function", fdict["name"], file=sys.stderr)
	
	locals()[fdict["name"]] = function_generator(fdict)


