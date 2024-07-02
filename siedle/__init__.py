import logging
import os
import time
import urllib.parse
import uuid
import requests
from requests.auth import HTTPBasicAuth
from requests.compat import json
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import LegacyApplicationClient
from asyncio import *
from push_receiver import register, listen

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://sus2.siedle.com/sus2"

OAUTH_URL = BASE_URL + "/oauth/token"
REFRESH_URL = OAUTH_URL
ENDPOINT_URL = "/api/endpoint/v1/endpoint"

S_NAME = "vIACY5qBrBgkB/wZ4cW+zQ=="
TOKENTYPE = "com.siedle.sus.app.prod"
NOTIFICATIONTYPE = "UserNotification"

class Siedle:
    def __init__(
                    self, 
                    token_cache_file=None,
                    token=None,
                    setupInfo=None,
                    cache_ttl=270
                ):
        self._token = token
        self._token_cache_file = token_cache_file
        self._cache_ttl = cache_ttl
        self._cache = {}
        self._deviceId = None
        self._client_id = "app"
        self._client: OAuth2Session = None
        self._extra = {
            'client_id': self.client_id,
        }
        
        if token is None and token_cache_file is None and setupInfo is None:
            print(
                "You need to supply a token or a cached token file or setupInfo"
            )
        else:
            if setupInfo is None:
                if (
                    self._token_cache_file is not None
                    and self._token is None
                    and os.path.exists(self._token_cache_file)
                ):
                    with open(self._token_cache_file, "r") as f:
                        self._token = json.load(f)

                if self._token is not None:
                    # force token refresh
                    self._token["expires_at"] = time.time() - 10
                    self._token["expires_in"] = "-30"
                    self.refreshToken()
            else:
                self.authorize(setupInfo)
                
                
        
                

    def _tokenSaver(self, token):
        self._token = token        
        if self._token_cache_file is not None:
            with os.fdopen(
                os.open(
                    self._token_cache_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                ),
                "w",
            ) as f:
                return json.dump(token, f)


    def authorize(self, setupInfo):
        susUrl = setupInfo["susUrl"]
        endpointTransferSecret = setupInfo["endpointTransferSecret"]
        endpointSetupKey = setupInfo["endpointSetupKey"]  # ist x-api-key in request an endpoint
        self.deviceId = uuid.uuid4()
        
        headers = {
            "x-api-key": endpointSetupKey, 
            "user-agent": "SiedleUnterwegs/356 CFNetwork/1402.0.8 Darwin/22.2.0",
            "content-type": "application/json"
            }
        
        response = requests.post(BASE_URL + ENDPOINT_URL, json = {"type": "IOS_APP"}, headers = headers).json()
        
        
        
        headersOauth = {
            "user-agent": "SiedleUnterwegs/356 CFNetwork/1402.0.8 Darwin/22.2.0",
            "content-type": "application/x-www-form-urlencoded"
            }
        

        client_id="app"
        username=response["username"]
        password=response["password"]
        
        self._client = OAuth2Session(client=LegacyApplicationClient(client_id="app"), token_updater=self._tokenSaver)
        self._token = self._client.fetch_token(token_url=OAUTH_URL,
        username=username, password=password, client_id=client_id,
        headers=headersOauth, device_id=self.deviceId)
    
    def refreshToken(self):
        self._client = OAuth2Session(self._client_id, token=self._token, auto_refresh_url=REFRESH_URL,
        auto_refresh_kwargs=self._extra, token_updater=self._tokenSaver)

    def _get(self, endpoint, **params):
        """Siedle get request method."""

        query_string = urllib.parse.urlencode(params)
        url = BASE_URL + endpoint + "?" + query_string
        try:
            response: requests.Response = self._client.get(
                url, client_id=self._client_id
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            _LOGGER.error("HTTP Error Siedle API: %s" % e)
            if e.response.status_code == 401:
                self._lyricReauth()
        except requests.exceptions.RequestException as e:
            # print("Error Lyric API: %s with data: %s" % (e, data))
            _LOGGER.error("Error Siedle API: %s" % e)

    def _post(self, endpoint, data, **params):
        """Siedle post request method."""

        query_string = urllib.parse.urlencode(params)
        url = BASE_URL + endpoint + "?" + query_string
        try:
            response: requests.Response = self._client.post(
                url,
                json=data,
                client_id=self._client_id,
            )
            response.raise_for_status()
            return response.status_code
        except requests.HTTPError as e:
            _LOGGER.error("HTTP Error Siedle API: %s" % e)
            if e.response.status_code == 401:
                self.refreshToken()
                _LOGGER.info("Retrying with new Token...")
                try:
                    response: requests.Response = self._client.post(
                        url,
                        json=data,
                        client_id=self._client_id,
                    )
                    response.raise_for_status()
                    return response.status_code
                except requests.HTTPError as e:
                    _LOGGER.error("HTTP Error Siedle API: %s" % e)
        except requests.exceptions.RequestException as e:
            # print("Error Lyric API: %s with data: %s" % (e, data))
            _LOGGER.error("Error Siedle API: %s with data: %s" % (e, data))


    
    def openDoor():
        
        pass
    
    def turnOnLight():
        
        pass
    
    def getStatus():
        
        pass
    
    def establishSipConnection():
        
        pass
    
    def on_notification(self, obj, notification, data_message):
        idstr = data_message.persistent_id + "\n"

        # check if we already received the notification
        with open("persistent_ids.txt", "r") as f:
            if idstr in f:
                return

        # new notification, store id so we don't read it again
        with open("persistent_ids.txt", "a") as f:
            f.write(idstr)

        # print notification
        n = notification["notification"]
        text = n["title"]
        if n["body"]:
            text += ": " + n["body"]
        print(text)