
from .llapi import *
from .common import *

class CoapObserver():
	"""! This class is used to handle asynchronous requests. Besides requests with
	observe flag set, this class also handles non-observe requests as the same
	mechanisms are used in both cases.
	"""
	def __init__(self, tx_pdu=None, multiplier=None):
		from asyncio import Event
		
		self.tx_pdu = tx_pdu
		self.ev = Event()
		self.rx_msgs = []
		self._stop = False
		# if stays false, this observer is used to return only a single response
		self.observing = False
		self.multiplier = multiplier
		
		weakref.finalize(self, self.release)
	
	def release(self):
		self.stop()
	
	async def wait(self):
		"""! wait on the next response """
		if self.multiplier:
			await self.multiplier.process()
		
		# BUG for some reason, wait() returns True sometimes although is_set() immediately afterwards returns false
		while not self.ev.is_set():
			a = await self.ev.wait()
	
	def addResponse(self, rx_msg):
		if self._stop:
			return
		
		if not self.multiplier:
			rx_msg.make_persistent()
			
			if rx_msg.is_error():
				self.observing = False
		
		self.rx_msgs.append(rx_msg)
		
		self.ev.set()
	
	def __aiter__(self):
		return self
	
	async def __anext__(self):
		if len(self.rx_msgs) == 0:
			await self.wait()
		
		if self._stop:
			raise StopAsyncIteration()
		
		rv = self.rx_msgs.pop()
		
		if len(self.rx_msgs) == 0:
			self.ev.clear()
		
		return rv
	
	def stop(self):
		"""! stop observation """
		if self._stop:
			return
		
		if not self.multiplier:
			if self.observing:
				self.tx_pdu.cancelObservation()
		else:
			self.multiplier.removeSub(self)
		
		self._stop = True
		self.ev.set()

class CoapObserverMultiplier():
	"""! This class enables multiple clients to asynchronously wait on a single subscribed
	resource.
	"""
	def __init__(self, main_observer):
		self.main_observer = main_observer
		self.sub_observers = []
		self.waiting = False
		self.last_pdu = None
		
		weakref.finalize(self, self.release)
	
	def release(self):
		for sub in self.sub_observers:
			sub.stop()
	
	def getSubObserver(self):
		self.sub_observers.append( CoapObserver(multiplier=self) )
		
		# A regular observer would return the current value immediately. Here,
		# we simulate this behavior using the last, previously received PDU.
		if self.last_pdu:
			self.sub_observers[-1].addResponse(self.last_pdu)
		
		return self.sub_observers[-1]
	
	def removeSub(self, sub):
		self.sub_observers.remove(sub)
	
	async def process(self):
		if self.waiting:
			return
		self.waiting = True
		
		rx_pdu = await anext(self.main_observer)
		self.last_pdu = rx_pdu
		
		for ob in self.sub_observers:
			ob.addResponse(rx_pdu)
		
		self.waiting = False
