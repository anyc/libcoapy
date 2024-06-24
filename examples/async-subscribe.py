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
	# First, immediately return the response.
	resp = await session.query()
	print(resp.payload)
	
	# Second, get an async generator, ...
	observer = await session.query(observe=True)
	
	# stop observing after five seconds, ...
	asyncio.ensure_future(stop_observer(observer, 5))
	
	# and continuously print the received messages.
	async for resp in observer:
		print(resp.payload)
	
	# If the observer stopped, stop the event loop to terminate the process.
	loop.stop()

# create a task that is executed after the event loop started
asyncio.ensure_future(startup(), loop=loop)

try:
	loop.run_forever()
except KeyboardInterrupt:
	loop.stop()
