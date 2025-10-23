
from .llapi import *
from .common import *
from .CoapSession import *

class CoapContext():
	"""! a context is the main object for CoAP operations (see also \ref context of libcoap)"""
	def __init__(self):
		contexts.append(self)
		
		self.lcoap_ctx = coap_new_context(None);
		
		self.sessions = []
		self.resources = []
		self._loop = None
		self.pdu_cache = []
		self.coap_fd = -1
		
		self.resp_handler_obj = coap_response_handler_t(self.responseHandler)
		coap_register_response_handler(context=self.lcoap_ctx, handler=self.resp_handler_obj)
		
		self.event_handler_obj = coap_event_handler_t(self.eventHandler)
		coap_register_event_handler(self.lcoap_ctx, self.event_handler_obj)
		
		self.nack_handler_obj = coap_nack_handler_t(self.nackHandler)
		coap_register_nack_handler(self.lcoap_ctx, self.nack_handler_obj)
		
		self.setBlockMode(COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY)
		
		weakref.finalize(self, self.release)
	
	def eventHandler(self, ll_session, event_type):
		event_type = coap_event_t(event_type)
		session = coap_session_get_app_data(ll_session)
		
		if event_type == coap_event_t.COAP_EVENT_SERVER_SESSION_NEW:
			session = CoapSession(self, ll_session)
			
			# If we did not create the session, we have to increase the reference
			# counter as we call coap_session_release when releasing our session
			# object.
			coap_session_reference(ll_session);
			coap_session_set_app_data(ll_session, session)
			
			self.addSession(session)
		
		if getattr(self, "event_callback", None):
			ret = self.event_callback(self, session, event_type)
		else:
			ret = None
		
		if event_type == coap_event_t.COAP_EVENT_SERVER_SESSION_DEL:
			if session:
				coap_session_set_app_data(ll_session, None)
			
			if session:
				self.removeSession(session)
		
		if ret is None:
			return 0
		else:
			return int(ret)
	
	def nackHandler(self, ll_session, pdu, nack_type, mid):
		nack_type = coap_nack_reason_t(nack_type)
		session = coap_session_get_app_data(ll_session)
		
		if hasattr(self, "nack_callback"):
			self.nack_callback(self, session, pdu, nack_type, mid)
	
	def release(self):
		for session in self.sessions.copy():
			session.release()
		
		if self.lcoap_ctx:
			coap_free_context(self.lcoap_ctx)
			self.lcoap_ctx = None
		
		try:
			contexts.remove(self)
		except ValueError:
			pass
		if not contexts:
			coap_cleanup()
	
	def setBlockMode(self, mode):
		"""! to choose how much libcoap will help while receiving large data """
		coap_context_set_block_mode(self.lcoap_ctx, mode)
	
	def newSession(self, *args, **kwargs):
		session = CoapClientSession(self, *args, **kwargs)
		
		return session
	
	def addSession(self, session):
		self.sessions.append(session)
	
	def removeSession(self, session):
		try:
			self.sessions.remove(session)
		except ValueError:
			pass
		session.release()
	
	def parse_uri(self, uri_str):
		uri = coap_uri_t()
		
		if isinstance(uri_str, str):
			uri.bytes = uri_str.encode()
		else:
			uri.bytes = uri_str
		
		coap_split_uri(ct.cast(ct.c_char_p(uri.bytes), ct.POINTER(ct.c_uint8)), len(uri.bytes), ct.byref(uri))
		
		return uri
	
	def get_addr_info(self, uri, ai_hint_flags=None):
		import socket
		
		if ai_hint_flags is None:
			ai_hint_flags = 0
		
		try:
			addr_info = coap_resolve_address_info(ct.byref(uri.host), uri.port, uri.port, uri.port, uri.port,
				ai_hint_flags, 1 << uri.scheme, coap_resolve_type_t.COAP_RESOLVE_TYPE_REMOTE);
		except NullPointer as e:
			raise UnresolvableAddress(uri, context=self)
		
		return addr_info
	
	def addEndpoint(self, uri):
		self.ep = CoapEndpoint(self, uri)
		
		return self.ep
	
	def addResource(self, resource):
		self.resources.append(resource)
		
		coap_add_resource(self.lcoap_ctx, resource.lcoap_rs)
	
	def getResource(self, uri):
		for resource in self.resources:
			if resource.uri == uri:
				return resource
		
		return None
	
	@staticmethod
	def _verify_psk_sni_callback(sni, session, self):
		result = coap_dtls_spsk_info_t()
		
		if hasattr(self, "verify_psk_sni_callback"):
			hint, key = self.verify_psk_sni_callback(self, sni, session)
		else:
			hint = getattr(self, "psk_hint", "")
			key = getattr(self, "psk_key", "")
		
		if isinstance(hint, str):
			hint = hint.encode()
		if isinstance(key, str):
			key = key.encode()
		
		result.hint.s = bytes2uint8p(hint)
		result.key.s = bytes2uint8p(key)
		
		result.hint.length = len(hint)
		result.key.length = len(key)
		
		session.dtls_spsk_sni_cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(session.dtls_spsk_sni_cb_data, ct.c_void_p).value
	
	@staticmethod
	def _verify_id_callback(identity, session, self):
		result = coap_bin_const_t()
		
		if hasattr(self, "verify_id_callback"):
			key = self.verify_id_callback(self, sni, session)
		else:
			key = getattr(self, "psk_key", "")
		
		if isinstance(key, str):
			key = key.encode()
		
		result.s = bytes2uint8p(key)
		
		result.length = len(key)
		
		session.dtls_spsk_id_cb_data = ct.byref(result)
		
		# for some reason, ctypes expects an integer that it converts itself to c_void_p
		# https://bugs.python.org/issue1574593
		return ct.cast(session.dtls_spsk_id_cb_data, ct.c_void_p).value
	
	def setup_dtls_psk(self, hint=None, key=None):
		self.dtls_spsk = coap_dtls_spsk_t()
		
		self.dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION
		
		self.dtls_spsk.ct_validate_sni_call_back = coap_dtls_psk_sni_callback_t(self._verify_psk_sni_callback)
		self.dtls_spsk.validate_sni_call_back = self.dtls_spsk.ct_validate_sni_call_back
		self.dtls_spsk.sni_call_back_arg = self
		self.dtls_spsk.ct_validate_id_call_back = coap_dtls_id_callback_t(self._verify_id_callback)
		self.dtls_spsk.validate_id_call_back = self.dtls_spsk.ct_validate_id_call_back
		self.dtls_spsk.id_call_back_arg = self
		
		# register an initial name and PSK that can get replaced by the callbacks above
		if hint is None:
			hint = getattr(self, "psk_hint", "")
		else:
			self.psk_hint = hint
		if key is None:
			key = getattr(self, "psk_key", "")
		else:
			self.psk_key = key
		
		if isinstance(hint, str):
			hint = hint.encode()
		if isinstance(key, str):
			key = key.encode()
		
		self.dtls_spsk.psk_info.hint.s = bytes2uint8p(hint)
		self.dtls_spsk.psk_info.key.s = bytes2uint8p(key)
		
		self.dtls_spsk.psk_info.hint.length = len(hint)
		self.dtls_spsk.psk_info.key.length = len(key)
		
		coap_context_set_psk2(self.lcoap_ctx, ct.byref(self.dtls_spsk))
	
	def responseHandler(self, lcoap_session, pdu_sent, pdu_recv, mid):
		session = coap_session_get_app_data(lcoap_session)
		if session:
			return session.responseHandler(pdu_sent, pdu_recv, mid)
		else:
			print("session object not set", lcoap_session, file=sys.stderr)
			return coap_response_t.COAP_RESPONSE_OK
	
	def io_process(self, timeout_ms=COAP_IO_WAIT):
		if timeout_ms < 0 or timeout_ms > COAP_IO_NO_WAIT:
			raise ValueError
		
		res = coap_io_process(self.lcoap_ctx, timeout_ms)
		if res < 0:
			raise CoapUnexpectedError("coap_io_process()")
		return res
	
	def loop(self, timeout_ms=None, io_timeout_ms=100, rx_wait_list=None):
		def all_responses_received(rx_wait_list):
			for token_hdl in rx_wait_list:
				if not token_hdl.get("ready", False):
					return False
			return True
		
		self.loop_stop = False
		if timeout_ms==None:
			while not self.loop_stop:
				self.io_process(io_timeout_ms)
				if rx_wait_list and all_responses_received(rx_wait_list):
					break
		else:
			while not self.loop_stop and timeout_ms > 0:
				timeout_ms -= self.io_process(min(io_timeout_ms, timeout_ms))
				if rx_wait_list and all_responses_received(rx_wait_list):
					break
	
	def stop_loop(self):
		if self._loop:
			self._loop.stop()
		else:
			self.loop_stop = True
	
	def setEventLoop(self, loop=None):
		if loop is None:
			from asyncio import get_event_loop
			try:
				self._loop = asyncio.get_running_loop()
			except RuntimeError:
				self._loop = asyncio.new_event_loop()
		else:
			self._loop = loop
		
		try:
			# this only returns a valid fd if the platform supports epoll
			self.coap_fd = coap_context_get_coap_fd(self.lcoap_ctx)
		except OSError as e:
			if verbosity > 1:
				print("coap_context_get_coap_fd failed", e)
			# we use -1 later to determine if we have to use the alternative
			# event handling
			self._loop.create_task(self.fd_timeout_cb(100))
		else:
			self._loop.add_reader(self.coap_fd, self.fd_callback)
		
		return self._loop
	
	async def fd_timeout_cb(self, timeout_ms):
		from asyncio import sleep
		
		await sleep(timeout_ms / 1000)
		
		self.fd_timeout_fut = None
		
		self.fd_callback()
	
	def fd_callback(self):
		if getattr(self, "fd_timeout_fut", False):
			self.fd_timeout_fut.cancel()
		
		try:
			self.io_process(COAP_IO_NO_WAIT)
		except CoapUnexpectedError as e:
			print("coap_io_process", e)
		
		if self.coap_fd >= 0:
			now = coap_tick_t()
			coap_ticks(ct.byref(now))
			
			timeout_ms = coap_io_prepare_epoll(self.lcoap_ctx, now)
		else:
			# get a list of all sockets from libcoap and add them manually to
			# the asyncio event loop
			if not getattr(self, "max_sockets", False):
				# just guessed values
				self.max_sockets = 8 + 2 * len(getattr(self, "interfaces", []))
			while True:
				read_fds_t = coap_fd_t * self.max_sockets
				write_fds_t = coap_fd_t * self.max_sockets
				read_fds = read_fds_t()
				write_fds = write_fds_t()
				have_read_fds = ct.c_uint()
				have_write_fds = ct.c_uint()
				rem_timeout_ms = ct.c_uint()
				
				coap_io_get_fds(self.lcoap_ctx, 
					read_fds, ct.byref(have_read_fds), self.max_sockets,
					write_fds, ct.byref(have_write_fds), self.max_sockets,
					ct.byref(rem_timeout_ms))
				
				timeout_ms = rem_timeout_ms.value
				
				if have_read_fds.value >= self.max_sockets or have_write_fds.value >= self.max_sockets:
					self.max_sockets *= 2
					continue
				
				for i in range(have_read_fds.value):
					self._loop.add_reader(read_fds[i], self.fd_callback)
				for i in range(have_write_fds.value):
					self._loop.add_writer(write_fds[i], self.fd_callback)
				
				if hasattr(self, "old_read_fds"):
					for fd in self.old_read_fds:
						if fd not in read_fds:
							self._loop.remove_reader(fd)
				if hasattr(self, "old_write_fds"):
					for fd in self.old_write_fds:
						if fd not in write_fds:
							self._loop.remove_writer(fd)
				
				self.old_read_fds = read_fds
				self.old_write_fds = write_fds
				
				break
		
		if timeout_ms > 0:
			self.fd_timeout_fut = self._loop.create_task(self.fd_timeout_cb(timeout_ms))
	
	@staticmethod
	def get_available_interfaces():
		import socket
		
		try:
			import ifaddr
			netifaces = None
		except ModuleNotFoundError:
			ifaddr = None
			try:
				import netifaces
			except ModuleNotFoundError:
				netifaces = None
		
		interfaces = {}
		if ifaddr:
			# interfaces = [ a.nice_name for a in ifaddr.get_adapters() ]
			for adapter in ifaddr.get_adapters():
				intf = lambda: None
				intf.name = adapter.nice_name
				intf.index = adapter.index
				intf.adapter = adapter
				
				intf.ips = []
				for ip in adapter.ips:
					if isinstance(ip.ip, str):
						intf.ips.append( (socket.AF_INET, ip.ip) )
					else:
						intf.ips.append( (socket.AF_INET6, ip.ip[0]) )
				
				interfaces[intf.name] = intf
		elif netifaces:
			if_names = netifaces.interfaces()
			
			for if_name in if_names:
				intf = lambda: None
				intf.name = if_name
				intf.adapter = None
				
				try:
					intf.index = socket.if_nametoindex(if_name)
				except:
					intf.index = None
				
				intf.ips = []
				for link in netifaces.ifaddresses(if_name).get(netifaces.AF_INET, []):
					intf.ips.append( (socket.AF_INET, link['addr']) )
				for link in netifaces.ifaddresses(if_name).get(netifaces.AF_INET6, []):
					intf.ips.append( (socket.AF_INET6, link['addr']) )
				
				interfaces[intf.name] = intf
		else:
			import fcntl
			import struct
			
			if_names = [i[1] for i in socket.if_nameindex()]
			
			def get_ip_address(ifname):
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				return socket.inet_ntoa(fcntl.ioctl(
					s.fileno(),
					0x8915,  # SIOCGIFADDR
					struct.pack('256s', ifname[:15].encode())
					)[20:24])
			
			for if_name in if_names:
				intf = lambda: None
				intf.name = if_name
				intf.adapter = None
				
				try:
					intf.index = socket.if_nametoindex(if_name)
				except:
					intf.index = None
				
				try:
					# TODO
					intf.ips = [(None, get_ip_address(intf.name))]
				except OSError as e:
					# [Errno 99] Cannot assign requested address
					# interfaces without IP?
					if e.errno != 99:
						print(intf.name, e)
					continue
				except Exception as e:
					print(intf.name, e)
					continue
				
				interfaces[intf.name] = intf
		
		return interfaces
	
	@staticmethod
	def get_distinct_ip(intf, ip):
		import ipaddress
		
		ipa = ipaddress.ip_address(ip)
		if ipa.is_link_local:
			if not sys.platform.startswith('win') or 'WINEPREFIX' in os.environ:
				result = ip+"%"+intf.name
			else:
				result = ip+"%"+str(intf.index)
		else:
			result = ip
		
		return result
	
	def enable_multicast(self, interfaces=None, mcast_address=None):
		import socket
		
		if interfaces:
			self.interfaces = interfaces
		else:
			self.interfaces = self.get_available_interfaces()
		
		self.multicast_interfaces = []
		for if_name, intf in self.interfaces.items():
			if if_name == "lo":
				continue
			
			if not intf.ips:
				continue
			
			families = [ family for family, ip in intf.ips ]
			
			if mcast_address:
				mcast_addr = mcast_address
			else:
				if socket.AF_INET6 in families:
					mcast_addr = COAP_MCAST_ADDR6_LL
				else:
					mcast_addr = COAP_MCAST_ADDR4
			
			# mcast_addr = self.get_distinct_ip(intf, mcast_addr)
			mcast_addr = mcast_addr+"%"+str(intf.index)
			
			try:
				if verbosity:
					print("enabling multicast on", if_name, "with address", mcast_addr, intf.index if isinstance(intf.index, int) else "")
				self._enable_multicast(mcast_addr, if_name)
			except Exception as e:
				print("enabling multicast on", if_name, "failed:", e)
			
			self.multicast_interfaces.append(intf)
	
	def _enable_multicast(self, multicast_address=COAP_MCAST_ADDR4, interface_name=None):
		coap_join_mcast_group_intf(self.lcoap_ctx, multicast_address, interface_name)

	def setKeepalive(self, interval_s):
		coap_context_set_keepalive(self.lcoap_ctx, interval_s)

class CoapEndpoint():
	"""! basically represents a socket """
	def __init__(self, ctx, uri):
		self.ctx = ctx
		
		self.uri = ctx.parse_uri(uri)
		self.addr_info = ctx.get_addr_info(self.uri)
		
		self.lcoap_endpoint = coap_new_endpoint(self.ctx.lcoap_ctx, self.addr_info.contents.addr, self.addr_info.contents.proto)
