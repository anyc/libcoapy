2025.08.22
----------
* new CoapPDU.getOptions()
* new CoapPDUResponse.is_error()
* new CoapContext.setKeepalive()
* new CoapContext.getResource()
* added CoapPDUResonse.request_pdu property
* llapi: updated from libcoap commit ea01661
* llapi: improved libcoap loader code
* llapi: various API fixes

2025.04.09
----------
* add CoapObserverMultiplier to enable multiple observations of the same resource
* CoapClientSession: call setup_connection late to simplify credentials setup
* added doxygen documentation

2024.12.17
----------

* use generated llapi.py file by genbindgen
* fragile event loop integration for Windows system replaced with new libcoap
  function `coap_io_get_fds()`, requires libcoap > v4.3.5 on Windows
