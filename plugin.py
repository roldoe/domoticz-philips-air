# Domoticz plugin to interact with Philips air purifiers
#
"""
<plugin key="pyaircontrol" name="Philips air purifier plugin" author="Devguy" version="1.0.0" wikilink="http://www.domoticz.com/wiki/plugins/plugin.html" externallink="https://github.com/bobzomer/domoticz_pyaircontrol">
    <description>
        <h2>Philips air purifier plugin</h2><br/>
        Domoticz plugin to interact with Philips air purifiers
        <h3>Configuration</h3>
        Configuration options...
    </description>
    <params>
        <param field="Address" label="Philips air purifier address" width="300px" required="true"/>
    </params>
</plugin>
"""
import threading
import time
import binascii
import hashlib
import json
import logging
import os

import Domoticz
import pyairctrl.coap_client
import pyairctrl.airctrl

from coapthon import defines
from coapthon.client.helperclient import HelperClient
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from collections import OrderedDict

class PyAirControl:
    connected = False
    lastUpdate = int(time.time())
    SECRET_KEY = "JiangPan"

    devices = [
        ("pwr", "Power", 244, 62, 0, 0, {}),
        ("pm25", "PM2.5", 243, 31, 0, 0, {"Custom": "1;µg/m³"}),
        ("rh", "Relative humidity", 81, 1, 0, 0, {}),
        ("rhset", "Target humidity", 244, 62, 18, 7, {"Scenes": "||||","LevelNames": "40%|50%|60%|Max", "LevelOffHidden": "false", "SelectorStyle": "0"}),
        ("iaql", "Allergen index", 249, 1, 0, 0, {}),
        ("temp", "Temperature", 80, 5, 0, 0, {}),
        ("mode", "Mode", 244, 62, 18, 7, {"LevelNames":"Auto|Allergen|Sleep|Manual","LevelOffHidden":"false","SelectorStyle":"1"}),
        ("om", "Fan speed", 244, 62, 18, 7, {"LevelNames":"Auto|Level 1|Level 2|Level 3|Turbo", "LevelOffHidden":"false","SelectorStyle":"0"}),
        ("aqil", "Light brightness", 244, 62, 18, 0, {"LevelNames":"0%|25%|50%|75%|100%","LevelOffHidden":"false","SelectorStyle":"0"}),
        ("aqit", "Air quality notification threshold", 0, 0, 0, 0, {}),
        ("uil", "Buttons light", 244, 62, 0, 0, {}),
        ("ddp", "Used index", 0, 0, 0, 0, {}),
        ("wl", "Water level", 0, 0, 0, 0, {}),
        ("cl", "Child lock", 0, 0, 0, 0, {}),
        ("dt", "Timer", 0, 0, 0, 0, {}),
        ("dtrs", "Timer", 0, 0, 0, 0, {}),
        ("fltt1", "HEPA filter type", 0, 0, 0, 0, {}),
        ("fltt2", "Active carbon filter type", 0, 0, 0, 0, {}),
        ("fltsts0", "Pre-filter and Wick", 243, 31, 0, 0, {"Custom": "1;Hours"}),
        ("fltsts1", "HEPA filter", 243, 31, 0, 0, {"Custom": "1;Hours"}),
        ("fltsts2", "Active carbon filter", 243, 31, 0, 0, {"Custom": "1;Hours"}),
        ("wicksts", "Wick filter", 243, 31, 0, 0, {"Custom": "1;Hours"}),
        ("err", "[ERROR] Message", 243, 22, 0, 0, {}),
    ]

    def __init__(self):
        self.client =  None
        self.protocol = None
        self.device_address = None

    def checkDevices(self):
        for index, (_, name, type_, subtype, switchtype, image, options) in enumerate(self.devices):
            if index + 1 not in Devices and type_ != 0:
                Domoticz.Log("Create device " + name + " image " + image)
                Domoticz.Device(Name=name, Unit=index + 1, Type=type_, Subtype=subtype, Switchtype=switchtype, Image=image, Options=options).Create()

    def updateDevices(self, status):
        try:
           self.lastUpdate = int(time.time())
           for index, (idee, name, type_, subtype, switchtype, _, options) in enumerate(self.devices):
               if type_ == 0:  # Not yet enabled
                   continue
               try:
                   idx = index+1
                   value = status[idee]
                   Domoticz.Log("Name " + idee + " value " + str(value))
                   if idee == "mode":
                       if value == "P":
                          Devices[idx].Update(nValue=0, sValue="0")
                       elif value == "A":
                          Devices[idx].Update(nValue=10, sValue="10")
                       elif value == "S":
                          Devices[idx].Update(nValue=20, sValue="20")
                       else:
                          Devices[idx].Update(nValue=30, sValue="30")
                   elif idee == "om":
                       if value == "a" or value=="s":
                          Devices[idx].Update(nValue=0, sValue="0")
                       elif value == "t":
                          Devices[idx].Update(nValue=0, sValue="40")
                       elif value.isnumeric():
                          nvalue = int(value) * 10
                          Devices[idx].Update(nValue=0, sValue=str(nvalue))
                   elif idee == "rhset":
                       Devices[idx].Update(nValue=0, sValue=(str(value-40)))
                   elif idee == "aqil":
                       if value == 0:
                            Devices[idx].Update(nValue=0,sValue="0")
                       elif value == 25:
                            Devices[idx].Update(nValue=0,sValue="10")
                       elif value == 50:
                            Devices[idx].Update(nValue=0,sValue="20")
                       elif value == 75:
                            Devices[idx].Update(nValue=0,sValue="30")
                       else:
                            Devices[idx].Update(nValue=0,sValue="40")
                   else:
                       if type_ == 244:
                          svalue = {'1': 'On','0':'Off'}.get(value,'Off')
                          Devices[idx].Update(nValue=int(value), sValue=svalue)
                       elif type(value) == int:
                          Devices[idx].Update(nValue=value,sValue=str(value))
                       else:
                          Devices[idx].Update(nValue=1, sValue=str(value))
               except KeyError:
                   pass
        except Exception as e:
            Domoticz.Error("Error...." + format(e))

    def onStart(self):
        self.device_address = Parameters["Address"].replace(" ", "")
        self.checkDevices()
        self.lastUpdate = int(time.time())

        try:
            Domoticz.Log("Connecting to Philips device on IP " + self.device_address + " using COAP")
            self.client = HelperClient(server=(self.device_address, 5683))
            self._sync()
            self._startObserver()
        except Exception as e:
            Domoticz.Error("Failed connecting to device...")

    def onStop(self):
        if self.client is not None:
           self.client.stop()
        connected = False

    def onConnect(self, Connection, Status, Description):

    def onMessage(self, Connection, Data):

    def onCommand(self, Unit, Command, Level, Hue):
        devname = self.devices[Unit-1][0]
        Domoticz.Log(
            "onCommand called for Unit " + str(Unit) + ": Parameter '" + str(devname) + "', Level: " + str(Level))

        if devname == "rhset":
             self._set(devname, Level+40)
        elif devname == "aqil":
             if Level ==  10:
                 self._set(devname, 25)
             elif Level == 20:
                 self._set(devname, 50)
             elif Level == 30:
                 self._set(devname, 75)
             elif Level == 40:
                 self._set(devname, 100)
             else: 
                 self._set(devname,0)
        elif devname == "mode":
             if Level == 0:
                 self._set(devname,"P")
             elif Level == 10:
                 self._set(devname,"A")
             elif Level == 20:
                 self._set(devname,"S")
             else:
                 self._set(devname,"M")
        elif devname == "om":
             if Level == 0:
                 self._set("mode","P")
             elif Level == 40:
                 self._set(devname,"t")
             else:
                 nvalue = int(Level / 10)
                 self._set(devname, str(nvalue))
        else:
           newvalue = {'On': '1','Off':'0'}.get(str(Command),'0')
           self._set(devname, str(newvalue))

    def onNotification(self, Name, Subject, Text, Status, Priority, Sound, ImageFile):

    def onDisconnect(self, Connection):

    def onHeartbeat(self):
        if (int(time.time()) - self.lastUpdate) > 600:
           self.connected = False
           Domoticz.Error("Lost connection to device, restart...")

           self.onStop()
           self.onStart()
        return

    def _sync(self):
        self.syncrequest = binascii.hexlify(os.urandom(4)).decode("utf8").upper()
        resp = self.client.post("/sys/dev/sync", self.syncrequest, timeout=5)
        if resp:
            self.client_key = resp.payload
            self.connected = True
        else:
            self.client.stop()
            self.connected = False
            raise Exception("sync timeout")

    def _startObserver(self):
        path = "/sys/dev/status"
        try:
            return self.client.observe(path, self._onData, 2)
        except Exception as e:
            Domoticz.Error("Error in _startObserver: " + str(e))

    def _onData(self,response):
        try:
            encrypted_payload = response.payload
            decrypted_payload = self._decrypt_payload(encrypted_payload)

            if decrypted_payload is not None:
                try:
                   jsondata =  json.loads(decrypted_payload, object_pairs_hook=OrderedDict)["state"]["reported"]
                except Exception as e:
                   Domoticz.Error("Error loading json data " + str(e))
                self.updateDevices(jsondata)
        except WrongDigestException:
            Domoticz.Error("WrongDigestException")
        except Exception as e:
            Domoticz.Error("Unexpected error " + str(e))

    def _set(self, key, value):
        path = "/sys/dev/control"
        try:
            payload = {
                "state": {
                    "desired": {
                        "CommandType": "app",
                        "DeviceId": "",
                        "EnduserId": "",
                        key: value,
                    }
                }
            }
            encrypted_payload = self._encrypt_payload(json.dumps(payload))
            response = self.client.post(path, encrypted_payload, self._onData, None, True)
            return response
        except Exception as e:
            Domoticz.Error("Unexpected error " + str(e))

    def _decrypt_payload(self, encrypted_payload):
        encoded_counter = encrypted_payload[0:8]
        aes = self._handle_AES(encoded_counter)
        encoded_message = encrypted_payload[8:-64].upper()
        digest = encrypted_payload[-64:]
        calculated_digest = self._create_digest(encoded_counter, encoded_message)
        if digest != calculated_digest:
            raise WrongDigestException
        decoded_message = aes.decrypt(bytes.fromhex(encoded_message))
        unpaded_message = unpad(decoded_message, 16, style="pkcs7")
        return unpaded_message.decode("utf8")

    def _encrypt_payload(self, payload):
        self._update_client_key()
        aes = self._handle_AES(self.client_key)
        paded_message = pad(bytes(payload.encode("utf8")), 16, style="pkcs7")
        encoded_message = binascii.hexlify(aes.encrypt(paded_message)).decode("utf8").upper()
        digest = self._create_digest(self.client_key, encoded_message)
        return self.client_key + encoded_message + digest

    def _create_digest(self, id, encoded_message):
        digest = (
            hashlib.sha256(bytes((id + encoded_message).encode("utf8")))
            .hexdigest()
            .upper()
        )
        return digest

    def _update_client_key(self):
        self.client_key = "{:x}".format(int(self.client_key, 16) + 1).upper()

    def getQueueSize(self):
        return self.client.getQueueSize()

    def _handle_AES(self, id):
        key_and_iv = hashlib.md5((self.SECRET_KEY + id).encode()).hexdigest().upper()
        half_keylen = len(key_and_iv) // 2
        secret_key = key_and_iv[0:half_keylen]
        iv = key_and_iv[half_keylen:]
        return AES.new(
            bytes(secret_key.encode("utf8")), AES.MODE_CBC, bytes(iv.encode("utf8"))
        )

global _plugin
_plugin = PyAirControl()


def onStart():
    global _plugin
    _plugin.onStart()


def onStop():
    global _plugin
    _plugin.onStop()


def onConnect(Connection, Status, Description):
    global _plugin
    _plugin.onConnect(Connection, Status, Description)


def onMessage(Connection, Data):
    global _plugin
    _plugin.onMessage(Connection, Data)


def onCommand(Unit, Command, Level, Hue):
    global _plugin
    _plugin.onCommand(Unit, Command, Level, Hue)


def onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile):
    global _plugin
    _plugin.onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile)


def onDisconnect(Connection):
    global _plugin
    _plugin.onDisconnect(Connection)


def onHeartbeat():
    global _plugin
    _plugin.onHeartbeat()


# Generic helper functions
def DumpConfigToLog():
    for x in Parameters:
        if Parameters[x] != "":
            Domoticz.Debug("'" + x + "':'" + str(Parameters[x]) + "'")
    Domoticz.Debug("Device count: " + str(len(Devices)))
    for x in Devices:
        Domoticz.Debug("Device:           " + str(x) + " - " + str(Devices[x]))
        Domoticz.Debug("Device ID:       '" + str(Devices[x].ID) + "'")
        Domoticz.Debug("Device Name:     '" + Devices[x].Name + "'")
        Domoticz.Debug("Device nValue:    " + str(Devices[x].nValue))
        Domoticz.Debug("Device sValue:   '" + Devices[x].sValue + "'")
        Domoticz.Debug("Device LastLevel: " + str(Devices[x].LastLevel))
    return

