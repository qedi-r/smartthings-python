#!/usr/bin/env python3.5

import sys
import json
import smartthings
import unittest

st_connection = smartthings.Connection(None)

uuid = "49012f27-17fa-448a-a59e-855210354737"
name = "Activity Right"
valid_evt = """
{"id":"702c2e70-eb55-11e6-9add-062fc1c67748","name":"switch","date":"2017-02-05T03:44:46+0000","data":null,"value":"turningOff","event":"turningOff","device":{"name":"Hue Bulb","displayName":"%s","id":"%s"}}
""" % (name, uuid)
invalid_evt_missing_device_id = """
{"id":"702c2e70-eb55-11e6-9add-062fc1c67748","name":"switch","date":"2017-02-05T03:44:46+0000","data":null,"value":"turningOff","event":"turningOff","device":{"name":"Hue Bulb","displayName":"%s"}}
""" % (name)
invalid_evt_wrong_device_id = """
{"id":"702c2e70-eb55-11e6-9add-062fc1c67748","name":"switch","date":"2017-02-05T03:44:46+0000","data":null,"value":"turningOff","event":"turningOff","device":{"name":"Hue Bulb","displayName":"%s", "id": "something_else"}}
""" % (name)
invalid_evt_invalid_json = """garbagio
{"id":"702c2e70-eb55-11e6-9add-062fc1c67748","name":"switch","date":"2017-02-05T03:44:46+0000","data":null,"value":"turningOff","event":"turningOff","device":{"name":"Hue Bulb","displayName":"%s", "id": "something"}}
""" % (name)

class  TestEvents(unittest.TestCase):
    #arrange
    #
    #act
    #
    #assert
    def test_switch_parseEvent_happyPath(self):
        sw = smartthings.Switch(st_connection, uuid, name)
        exception = False

        sw._parseEvent(valid_evt)

        #assert assumed no exception

    def test_switch_updateState_happyPath(self):
        sw = smartthings.Switch(st_connection, uuid, name)

        sw.updateState(valid_evt)

        self.assertEqual(sw.status, "off")

    def test_switch_parseEvent_invalidJson(self):
        #arrange
        sw = smartthings.Switch(st_connection, uuid, name)

        with self.assertRaises(json.decoder.JSONDecodeError):
            sw._parseEvent(invalid_evt_invalid_json)

    def test_switch_parseEvent_wrongDeviceId(self):
        #arrange
        sw = smartthings.Switch(st_connection, uuid, name)
        sw.on()
        exception = False

        with self.assertRaises(smartthings.EventMissingAttribute):
            sw._parseEvent(invalid_evt_missing_device_id)

    def test_switch_parseEvent_wrongDeviceId(self):
        #arrange
        sw = smartthings.Switch(st_connection, uuid, name)
        sw.on()
        exception = False

        with self.assertRaises(smartthings.EventUnexpectedDevice):
            sw._parseEvent(invalid_evt_wrong_device_id)


if __name__ == '__main__':
    unittest.main()

