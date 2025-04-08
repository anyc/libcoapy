{
	"project_name": "libcoap",
	"clibrary_path_env_vars": ["LIBCOAP_PATH", "LIBCOAPY_PATH", "LIBCOAPY_LIB"],
	"libname_pattern": {
		"dimensions": {
			"version": ["", "-3"],
			"ssl_lib": ["", "-openssl", "-gnutls"],
			"tag": [".so.3", ".so", ".dll"],
			},
		"pattern": "{clibrary}{version}{ssl_lib}{tag}",
		},
	
	"clang_args": ["-DCOAP_API=", "-DCOAP_DEPRECATED=", "-DCOAP_STATIC_INLINE=",],
	"opaque_types": ["coap_pdu_t", "coap_context_t",
		"coap_resource_t", "coap_session_t", "coap_oscore_conf_t",
		"coap_subscription_t", "coap_endpoint_t", "coap_socket_t",
		"coap_async_t", "coap_cache_key_t", "coap_cache_entry_t", "coap_attr_t",
		
		
		"fd_set", "epoll_event",
		],
	"ignore_structs": ["coap_string_t", "coap_str_const_t", "coap_binary_t", "coap_bin_const_t"],
	"include": { 2: ["sockaddr", "local"], 7: ["07-default-retval"], },
	"functions": {
		"coap_split_uri": {
			"arg_dirs": {
				3: ["in", "out"],
				},
			},
		"coap_resolve_address_info": {
			"arg_dirs": {
				1: ["in"],
				2: ["in"],
				3: ["in"],
				4: ["in"],
				5: ["in"],
				6: ["in"],
				7: ["in"],
				8: ["in"],
				},
			},
		"coap_new_context": {
			"arg_dirs": {
				1: ["in"],
				},
			},
		"coap_print_addr": {
			"arg_dirs": {
				"address": ["in"],
				},
			},
		"coap_split_uri": {
			"arg_dirs": {
				"uri": ["in","out"],
				},
			},
		"coap_uri_into_optlist": {
			"arg_dirs": {
				"uri": ["in"],
				"optlist_chain": ["out"],
				},
			},
		"coap_get_data_large": {
			"arg_dirs": {
				"len": ["in", "out"],
				"data": ["out"],
				"offset": ["in", "out"],
				"total": ["in", "out"],
				},
			},
		"coap_split_uri": {
			"expect": 0,
			},
		"coap_io_process": {
			"res_error": -1,
			},
		"coap_context_get_coap_fd": {
			"res_error": -1,
			},
		"coap_is_af_unix": {
			"llapi_check": False,
			},
		"coap_is_bcast": {
			"llapi_check": False,
			},
		"coap_is_mcast": {
			"llapi_check": False,
			},
		"coap_pdu_get_code": {
			"llapi_check": False,
			},
		"coap_pdu_get_type": {
			"llapi_check": False,
			},
		}
}
