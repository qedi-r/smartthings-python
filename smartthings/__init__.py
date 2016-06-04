
import requests
import json

import pprint
import logging

import http.client

http.client.HTTPConnection.debuglevel = 1

logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
logging.getLogger().setLevel(logging.DEBUG)

smartthings_log = logging.getLogger("smartthings")

requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

ST_UNKNOWN = "UNKNOWN"

class OAuthException(Exception):
    """ General OAuth Issues. See message for details """
    pass


SMARTTHINGS_LOGIN_HOSTNAME = "graph.api.smartthings.com"

class AuthExceptionNoAuthentication(Exception):
    pass

class Authentication:
    def __init__(self, oauth_client_id, oauth_client_secret, redirect_uri):
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.redirect_uri = redirect_uri
        self.app_uri = None
        
    def getOAuthLoginURL(self):
        return "https://%s/oauth/authorize?response_type=code&client_id=%s&scope=app&redirect_uri=%s" % (
            SMARTTHINGS_LOGIN_HOSTNAME,
            self.oauth_client_id,
            self.redirect_uri
        )

    def getAccessToken(self, code):
        r = requests.post("https://%s/oauth/token" % SMARTTHINGS_LOGIN_HOSTNAME, 
                data = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self.oauth_client_id,
                    "client_secret": self.oauth_client_secret,
                    "redirect_uri": self.redirect_uri
                }
            )

        r.raise_for_status()
        smartthings_log.log(logging.DEBUG, "Access Token: %s" % (r.json()["access_token"]))
        self.saveAccessToken(r.json())
        return r.json()

    def saveAccessToken(self, response):
        self.access_token = response["access_token"]
        self.expiry = response["expires_in"]
        self.scope = response["scope"]
        self.token_type = response["token_type"]

    def getAuthHeader(self):
        if self.access_token:
            return { "Authorization": "Bearer %s" % (self.access_token) }
        else:
            raise AuthExceptionNoAuthentication()


class Connection:
    def __init__(self, auth=None):
        self.devices = None
        self.auth = auth
        if auth:
            self.updateDevices()

    def setAuth(self, auth):
        self.auth = auth

    def _path_sanitize(self, path):
        if path.startswith("/"):
            path = path[1:]
        return path

    def _get(self, path):
        if self.auth.app_uri == None:
            self.auth.app_uri = "https://%s/" % (SMARTTHINGS_LOGIN_HOSTNAME)
            r = self._get("/api/smartapps/endpoints")
            info = r.json()
            self.auth.app_uri = info[0]["uri"]
            smartthings_log.log(logging.DEBUG, "Got app uri: %s" % self.auth.app_uri)
                
        path = self._path_sanitize(path)

        get_uri = "%s/%s" % ( self.auth.app_uri, path )
        smartthings_log.log(logging.DEBUG, "Getting: %s" % get_uri)
        r = requests.get(get_uri, headers=self.auth.getAuthHeader())
        r.raise_for_status()
        return r

    def _post(self, path, payload):
        path = self._path_sanitize(path)

        post_uri = "%s/%s" % ( self.auth.app_uri, path )
        smartthings_log.log(logging.DEBUG, "Posting to: %s" % post_uri)
        smartthings_log.log(logging.DEBUG, "Data: %s" % payload)

        header_list = self.auth.getAuthHeader()
        header_list["Content-Type"] = "application/json"

        r = requests.post(post_uri, headers=self.auth.getAuthHeader(), json=payload)
        r.raise_for_status()
        return r

    def updateDevices(self):
        deviceList = self._get('/list').json()

        self.devices = {}

        smartthings_log.log(logging.DEBUG, pprint.pformat(deviceList)) 

        for i in deviceList:
            if i["type"] == "switch":
                self.devices[i["id"]] = Switch(self, i["id"], i["label"])
            elif i["type"] == "lock":
                self.devices[i["id"]] = Lock(self, i["id"], i["label"])
            elif i["type"] == "presenceSensor":
                self.devices[i["id"]] = PresenceSensor(self, i["id"], i["label"])
            elif i["type"] == "contactSensor":
                self.devices[i["id"]] = ContactSensor(self, i["id"], i["label"])
            elif i["type"] == "motionSensor":
                self.devices[i["id"]] = MotionSensor(self, i["id"], i["label"])
            else:
                raise Exception("Unknown device type %s" % (i['type']))

    def getDevices(self, filter_type=None):
        if self.devices == None:
            self.updateDevices()
        if filter_type == None:
            return self.devices
        else:
            return [val for key,val in self.devices.items() if type(val) is filter_type]

class Thing:
    def __init__(self, connection, uuid, label):
        self.connection = connection
        self.uuid = uuid
        self.label = label
        self.status = ST_UNKNOWN 

    def getId(self):
        return self.uuid

    def getName(self):
        return self.label

    def getDevice(self):
        return self.connection._get("/device/%s" % self.uuid).json()

    def loadStatus(self):
        return self.connection._get("/device/%s/status" % self.uuid).json()

    def getStatus(self):
        if self.status == ST_UNKNOWN:
            self.status = self.loadStatus()
        return self.status

    def subscribe(self):
        #TODO
        return self

    def _command(self, command, args=None):
        payload = {"command": command}
        if args:
            payload["arguments"] = args
        return self.connection._post("/device/%s" % self.uuid, payload)


class Switch(Thing):
    def off(self):
        return self._command("off")

    def on(self):
        return self._command("on")

    def is_on(self):
        return self.status["switch"] == "on"

class Lock(Thing):
    def lock(self):
        return self._command("lock")

    def unlock(self):
        return self._command("unlock")

class PresenceSensor(Thing):
    pass

class ContactSensor(Thing):
    pass

class MotionSensor(Thing):
    pass

