Domoticz python plugin for controlling Philips Air Purifiers

This plugin is tested with a COAP compatible device like the AC3829/10 (2020).
The logic is based on the py-air-control python module, but that module contained fundamental COAP problems that will temporarily brick your device after a certain time.

Installation
---
Python 3.4+ is required and a plugin for COAP. Install with pip3:

```
sudo pip3 install -U git+https://github.com/Tanganelli/CoAPthon3@3dc7e5c8d64cc1b10ed36141836ec5ba94fba0c7
```

Create in the domoticz/plugins folder another directory called 'Philips'.
Move the plugin.py into this directory and restart domoticz

Configuration
---
After installation you need to figure out the IP of the device. This plugin only works with COAP compatible devices. 


