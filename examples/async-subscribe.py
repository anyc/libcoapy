import asyncio
from libcoapy import *

# Usage: simply start coap-server-openssl on the same system and execute this script

if len(sys.argv) < 2:
	uri_str = "coap://localhost/time"
else:
	uri_str = sys.argv[1]

try:
	loop = asyncio.get_running_loop()
except RuntimeError:
	loop = asyncio.new_event_loop()

ctx = CoapContext()
ctx.setEventLoop(loop)

session = ctx.newSession(uri_str)

# callback that stops the observation after a specified time
async def stop_observer(observer, timeout):
	await asyncio.sleep(timeout)
	observer.stop()

# startup task
async def startup():
	# first, immediately return the response
	resp = await session.query(observe=False)
	print(resp.payload)
	
	# second, return a async generator...
	observer = await session.query(observe=True)
	
	# and stop observing after five seconds
	asyncio.ensure_future(stop_observer(observer, 5))
	
	# continuously print the received messages
	async for resp in observer:
		print(resp.payload)
	
	# if the observer stopped, stop the event loop
	loop.stop()

# create a task that is executed after the event loop started
asyncio.ensure_future(startup(), loop=loop)

try:
	loop.run_forever()
except KeyboardInterrupt:
	loop.stop()
