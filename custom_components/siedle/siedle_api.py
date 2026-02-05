import logging
import os
import time
import urllib.parse
import uuid
import hmac
import hashlib
import json
import base64
import requests
import ssl
import socket
import re
import threading
import asyncio
from datetime import datetime
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import LegacyApplicationClient

# AES decryption for setupData (required for HMAC signatures)
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from push_receiver import register, listen
    PUSH_RECEIVER_AVAILABLE = True
except (ImportError, TypeError, Exception):
    # push_receiver may fail with protobuf compatibility issues
    register = None
    listen = None
    PUSH_RECEIVER_AVAILABLE = False

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

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
        self._setupData = None  # Encrypted setupData from server
        self._sharedSecret = None  # Decrypted secret for HMAC signatures!
        self._transferSecret = None  # From QR code, used to decrypt setupData
        self._endpoint_id = None
        self._peer_id = None  # Door station peer ID (for MQTT topics)
        self._device_id = None  # Device ID (for MQTT topics)
        self._contacts = []
        self._config = {}
        self._mqtt_client = None
        self._mqtt_connected = False
        self._mqtt_callbacks = []
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

    @property
    def client_id(self):
        return self._client_id
    
    @property
    def deviceId(self):
        return self._deviceId
    
    @deviceId.setter
    def deviceId(self, value):
        self._deviceId = value

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

    def _decrypt_setup_data(self, encrypted_setup_data: str, transfer_secret: str) -> bytes:
        """
        Decrypt setupData from server using transferSecret from QR code.
        
        The Siedle app encrypts the sharedSecret (used for HMAC signatures) with
        AES-CBC and the transferSecret from the QR code. This method decrypts it.
        
        Based on reverse-engineered CryptoCbc.java from Siedle Android app:
        - Cipher: AES/CBC/PKCS5PADDING
        - IV: 16 bytes of 0x00
        - Key: transferSecret (hex-encoded in QR code)
        
        Args:
            encrypted_setup_data: Hex-encoded encrypted data from API
            transfer_secret: Hex-encoded key from QR code (endpointTransferSecret)
            
        Returns:
            Decrypted sharedSecret as bytes
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("pycryptodome is required for setupData decryption. Install with: pip install pycryptodome")
        
        # Convert hex strings to bytes
        encrypted_bytes = bytes.fromhex(encrypted_setup_data)
        key_bytes = bytes.fromhex(transfer_secret)
        
        # IV is 16 zero bytes (as per CryptoCbc.java)
        iv = bytes(16)
        
        # Create AES-CBC cipher and decrypt
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        # Remove PKCS5/PKCS7 padding
        try:
            decrypted = unpad(decrypted_padded, AES.block_size)
        except ValueError as e:
            _LOGGER.error(f"Failed to unpad decrypted data: {e}")
            _LOGGER.debug(f"Decrypted padded data (hex): {decrypted_padded.hex()}")
            # Try without unpadding (some implementations don't pad)
            decrypted = decrypted_padded.rstrip(b'\x00')
        
        _LOGGER.debug(f"Decrypted sharedSecret: {decrypted.hex()} ({len(decrypted)} bytes)")
        return decrypted


    def authorize(self, setupInfo):
        # Support both QR code formats
        if 'endpointSetupKey' in setupInfo:
            setupKey = setupInfo["endpointSetupKey"]
        else:
            setupKey = setupInfo["setupKey"]
        
        # Store transferSecret if available (for pairing/activation)
        self._transferSecret = setupInfo.get("endpointTransferSecret")
        
        self.deviceId = str(uuid.uuid4()).upper()
        
        headers = {
            "x-api-key": setupKey, 
            "user-agent": "SiedleUnterwegs/356 CFNetwork/1402.0.8 Darwin/22.2.0",
            "content-type": "application/json"
            }
        
        _LOGGER.info("Registering endpoint with Siedle server...")
        http_response = requests.post(
            BASE_URL + ENDPOINT_URL, 
            json={
                "type": "IOS_APP"
            }, 
            headers=headers
        )
        
        # Check HTTP status (200 OK or 201 Created)
        if http_response.status_code not in (200, 201):
            _LOGGER.error(f"Siedle API returned status {http_response.status_code}: {http_response.text}")
            raise Exception(f"API returned status {http_response.status_code}")
        
        try:
            response = http_response.json()
        except Exception as e:
            _LOGGER.error(f"Failed to parse API response as JSON: {http_response.text}")
            raise
        
        # Log response for debugging
        _LOGGER.debug(f"API Response: {response}")
        
        # Check for required fields
        if "id" not in response:
            _LOGGER.error(f"API response missing 'id' field. Response: {response}")
            raise KeyError("id field missing in API response - check if setupKey is valid")
        
        # Store important data
        self._endpoint_id = response["id"]
        self._setupData = response["setupData"]  # Encrypted setupData from server
        _LOGGER.info(f"Endpoint registered with ID: {self._endpoint_id}")
        
        # Decrypt setupData to get sharedSecret for HMAC signatures
        # This is CRITICAL - the setupData is AES-CBC encrypted with the transferSecret!
        if self._transferSecret:
            try:
                self._sharedSecret = self._decrypt_setup_data(self._setupData, self._transferSecret)
                _LOGGER.info(f"Successfully decrypted sharedSecret ({len(self._sharedSecret)} bytes)")
            except Exception as e:
                _LOGGER.error(f"Failed to decrypt setupData: {e}")
                _LOGGER.warning("Door/light control may not work without decrypted sharedSecret!")
        else:
            _LOGGER.warning("No transferSecret available - cannot decrypt setupData!")
            _LOGGER.warning("Door/light control will likely fail. Please rescan QR code.")
        
        headersOauth = {
            "user-agent": "SiedleUnterwegs/356 CFNetwork/1402.0.8 Darwin/22.2.0",
            "content-type": "application/x-www-form-urlencoded"
            }
        

        client_id = "app"
        username = response["username"]
        password = response["password"]
        
        _LOGGER.info("Fetching OAuth token...")
        _LOGGER.debug(f"OAuth URL: {OAUTH_URL}")
        _LOGGER.debug(f"Username: {username}")
        
        # Try direct requests call to see exact error
        try:
            oauth_response = requests.post(
                OAUTH_URL,
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                    "client_id": client_id
                },
                headers=headersOauth
            )
            _LOGGER.debug(f"OAuth Response Status: {oauth_response.status_code}")
            _LOGGER.debug(f"OAuth Response Body: {oauth_response.text}")
            
            if oauth_response.status_code == 200:
                self._token = oauth_response.json()
                self._client = OAuth2Session(client=LegacyApplicationClient(client_id="app"), token_updater=self._tokenSaver)
                self._client.token = self._token
            else:
                _LOGGER.error(f"OAuth failed with status {oauth_response.status_code}: {oauth_response.text}")
                raise Exception(f"OAuth authentication failed: {oauth_response.text}")
        except Exception as e:
            _LOGGER.error(f"OAuth token fetch failed: {e}")
            _LOGGER.error(f"This might indicate wrong credentials or API changes")
            raise
        
        _LOGGER.info("Authorization successful!")
        
        # Load initial configuration and contacts
        self._load_config()
        self._load_contacts()
    
    def refreshToken(self):
        """Refresh OAuth token"""
        self._client = OAuth2Session(
            self._client_id, 
            token=self._token, 
            auto_refresh_url=REFRESH_URL,
            auto_refresh_kwargs=self._extra, 
            token_updater=self._tokenSaver
        )

    def _generate_signature(self, action: str, contact_id: str, timestamp: str = None) -> dict:
        """
        Generate HMAC-SHA256 signature for door/light control requests.
        
        Based on reverse-engineered Siedle Android app SignatureHelper.java:
        The signature is computed as:
            HMAC-SHA256(sharedSecret, action + connectionId + timestamp + contactId)
        
        Where:
            - sharedSecret = DECRYPTED setupData (AES-CBC decrypted with transferSecret)
            - action = "DOOROPENER" or "DOORLIGHT" (UPPERCASE!)
            - connectionId = endpoint_id (UUID)
            - timestamp = ISO 8601 timestamp "YYYY-MM-DDTHH:MM:SS"
            - contactId = door contact UUID
        
        IMPORTANT: The setupData from the API is AES-CBC encrypted!
        It must be decrypted with the transferSecret from the QR code first.
        
        Args:
            action: "DOOROPENER" or "DOORLIGHT" (must be uppercase)
            contact_id: UUID of the door contact
            timestamp: ISO 8601 timestamp string, defaults to current UTC time
            
        Returns:
            dict with 'timestamp' and 'signature'
        """
        if self._endpoint_id is None:
            raise ValueError("endpoint_id not available. Authorization required.")
        
        # Use decrypted sharedSecret if available, otherwise fall back to raw setupData
        if self._sharedSecret is not None:
            secret_bytes = self._sharedSecret
            _LOGGER.debug("Using decrypted sharedSecret for signature")
        elif self._setupData is not None:
            _LOGGER.warning("sharedSecret not available, using raw setupData (may not work!)")
            try:
                # Try hex first (most common)
                secret_bytes = bytes.fromhex(self._setupData)
            except ValueError:
                # Fall back to base64
                secret_bytes = base64.b64decode(self._setupData)
        else:
            raise ValueError("Neither sharedSecret nor setupData available. Authorization required.")
        
        if timestamp is None:
            # Generate ISO 8601 timestamp without microseconds (matches app format)
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Build message: action + connectionId + timestamp + contactId
        # This is the correct order as per SignatureHelper.java!
        message = f"{action}{self._endpoint_id}{timestamp}{contact_id}"
        
        _LOGGER.debug(f"Signature input: action={action}, connectionId={self._endpoint_id}, timestamp={timestamp}, contactId={contact_id}")
        _LOGGER.debug(f"Signature message: {message}")
        _LOGGER.debug(f"Secret bytes (first 8): {secret_bytes[:8].hex() if len(secret_bytes) >= 8 else secret_bytes.hex()}")
        
        # HMAC-SHA256 signature
        signature = hmac.new(
            secret_bytes,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        _LOGGER.debug(f"Generated signature: {signature}")
        
        return {
            "timestamp": timestamp,
            "signature": signature
        }

    def _get(self, endpoint, **params):
        """Siedle GET request method."""
        query_string = urllib.parse.urlencode(params)
        url = BASE_URL + endpoint
        if query_string:
            url += "?" + query_string
            
        try:
            response: requests.Response = self._client.get(
                url,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            _LOGGER.error("HTTP Error Siedle API: %s" % e)
            if e.response.status_code == 401:
                self.refreshToken()
                response = self._client.get(url, timeout=30)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            _LOGGER.error("Error Siedle API: %s" % e)
            raise

    def _post(self, endpoint, data, **params):
        """Siedle POST request method."""
        query_string = urllib.parse.urlencode(params)
        url = BASE_URL + endpoint
        if query_string:
            url += "?" + query_string
            
        try:
            response: requests.Response = self._client.post(
                url,
                json=data,
                timeout=30
            )
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.HTTPError as e:
            _LOGGER.error("HTTP Error Siedle API: %s" % e)
            if e.response.status_code == 401:
                self.refreshToken()
                _LOGGER.info("Retrying with new Token...")
                response = self._client.post(url, json=data, timeout=30)
                response.raise_for_status()
                return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            _LOGGER.error("Error Siedle API: %s with data: %s" % (e, data))
            raise

    def _put(self, endpoint, data, **params):
        """Siedle PUT request method."""
        query_string = urllib.parse.urlencode(params)
        url = BASE_URL + endpoint
        if query_string:
            url += "?" + query_string
            
        try:
            response: requests.Response = self._client.put(
                url,
                json=data,
                timeout=30
            )
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.HTTPError as e:
            _LOGGER.error("HTTP Error Siedle API: %s" % e)
            if e.response.status_code == 401:
                self.refreshToken()
                response = self._client.put(url, json=data, timeout=30)
                response.raise_for_status()
                return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            _LOGGER.error("Error Siedle API: %s with data: %s" % (e, data))
            raise


    def _load_endpoint_info(self):
        """Load endpoint info including deviceId and peerId"""
        try:
            endpoint_info = self._get("/api/endpoint/v1/endpoint")
            self._endpoint_id = endpoint_info.get("id", self._endpoint_id)
            self._peer_id = endpoint_info.get("peerId")
            self._device_id = endpoint_info.get("deviceId")
            _LOGGER.info(f"Endpoint info loaded: id={self._endpoint_id}, peerId={self._peer_id}, deviceId={self._device_id}")
            return endpoint_info
        except Exception as e:
            _LOGGER.error(f"Failed to load endpoint info: {e}")
            return None

    def _load_config(self):
        """Load endpoint configuration (SIP, MQTT, etc.)"""
        try:
            # Also load endpoint info for deviceId and peerId
            self._load_endpoint_info()
            self._config = self._get("/api/endpoint/v1/endpoint/config")
            _LOGGER.info("Configuration loaded successfully")
        except Exception as e:
            _LOGGER.error(f"Failed to load config: {e}")
    
    def _load_contacts(self):
        """Load door contacts"""
        try:
            result = self._get("/api/endpoint/v1/endpoint/contacts", type="DOOR")
            if result:
                self._contacts = result.get("contacts", [])
            else:
                self._contacts = []
            _LOGGER.info(f"Loaded {len(self._contacts)} door contacts")
        except Exception as e:
            _LOGGER.error(f"Failed to load contacts: {e}")
    
    def activate_endpoint(self):
        """
        Activate/pair endpoint with door station using transferSecret.
        This should be called after initial setup when the user presses 
        the doorbell button to authorize the new endpoint.
        
        Returns:
            Response dict with activation status
        """
        if not hasattr(self, '_transferSecret') or not self._transferSecret:
            raise ValueError("Transfer secret not available. Required for endpoint activation.")
        
        _LOGGER.info("Activating endpoint with door station...")
        _LOGGER.info("Please press the doorbell button now to complete pairing!")
        
        # Try different possible endpoints
        endpoints_to_try = [
            f"/api/endpoint/v1/endpoint/transfer",
            f"/api/endpoint/v1/endpoint/{self._endpoint_id}/activate",
            f"/api/endpoint/v1/endpoint/{self._endpoint_id}/pair",
            f"/api/endpoint/v1/transfer",
        ]
        
        for endpoint in endpoints_to_try:
            try:
                _LOGGER.info(f"Trying activation endpoint: {endpoint}")
                
                # Try POST with transferSecret
                response = self._post(endpoint, {
                    "transferSecret": self._transferSecret
                })
                _LOGGER.info(f"Endpoint activation successful via {endpoint}! Response: {response}")
                return response
            except Exception as e:
                _LOGGER.debug(f"Endpoint {endpoint} failed: {e}")
                continue
        
        # If all failed, try PUT to main endpoint
        try:
            _LOGGER.info("Trying PUT to /api/endpoint/v1/endpoint with transferSecret")
            response = self._put("/api/endpoint/v1/endpoint", {
                "transferSecret": self._transferSecret
            })
            _LOGGER.info(f"Endpoint activation successful via PUT! Response: {response}")
            return response
        except Exception as e:
            _LOGGER.error(f"All activation attempts failed. Last error: {e}")
            _LOGGER.info("The endpoint might already be activated, or activation requires a different method.")
            _LOGGER.info(f"TransferSecret available: {self._transferSecret[:20]}...")
            raise

    def get_config(self):
        """Get endpoint configuration (SIP, MQTT, device info)"""
        if not self._config:
            self._load_config()
        return self._config
    
    def get_sip_credentials(self):
        """Get SIP credentials for audio/video calls"""
        config = self.get_config()
        return config.get("sip") if config else None
    
    def get_mqtt_credentials(self):
        """Get MQTT credentials for real-time events"""
        config = self.get_config()
        return config.get("mqtt") if config else None
    
    def get_contacts(self, contact_type="DOOR", force_refresh=False):
        """
        Get contacts (door stations, etc.)
        
        Args:
            contact_type: Type of contact (DOOR, PHONE, PEER)
            force_refresh: Force reload from server
            
        Returns:
            List of contact dictionaries
        """
        if force_refresh or not self._contacts:
            self._load_contacts()
        
        if contact_type:
            return [c for c in self._contacts if c.get("type") == contact_type]
        return self._contacts
    
    def openDoor(self, contact_id=None):
        """
        Open/release a door
        
        Args:
            contact_id: ID of the door contact. If None, uses first available door
            
        Returns:
            Response dict with id, timestamp, signature
        """
        if contact_id is None:
            contacts = self.get_contacts(contact_type="DOOR")
            if not contacts:
                raise ValueError("No door contacts found")
            contact_id = contacts[0]["id"]
            _LOGGER.info(f"Using first door contact: {contact_id}")
        
        # Generate signed request with correct parameters:
        # action="DOOROPENER" (uppercase as per Android app)
        signed_data = self._generate_signature(action="DOOROPENER", contact_id=contact_id)
        
        _LOGGER.info(f"Opening door {contact_id}...")
        endpoint = f"/api/endpoint/v1/endpoint/contacts/{contact_id}/doorOpenerRequest"
        response = self._post(endpoint, signed_data)
        
        _LOGGER.info(f"Door opened successfully! Response: {response}")
        return response
    
    def turnOnLight(self, contact_id=None):
        """
        Toggle door light
        
        Args:
            contact_id: ID of the door contact. If None, uses first available door
            
        Returns:
            Response dict with id, timestamp, signature
        """
        if contact_id is None:
            contacts = self.get_contacts(contact_type="DOOR")
            if not contacts:
                raise ValueError("No door contacts found")
            contact_id = contacts[0]["id"]
            _LOGGER.info(f"Using first door contact: {contact_id}")
        
        # Generate signed request with correct parameters:
        # action="DOORLIGHT" (uppercase as per Android app)
        signed_data = self._generate_signature(action="DOORLIGHT", contact_id=contact_id)
        
        _LOGGER.info(f"Toggling light for door {contact_id}...")
        endpoint = f"/api/endpoint/v1/endpoint/contacts/{contact_id}/doorLightRequest"
        response = self._post(endpoint, signed_data)
        
        _LOGGER.info(f"Light toggled successfully! Response: {response}")
        return response
    
    def getStatus(self):
        """
        Get current endpoint status and configuration
        
        Returns:
            Dict with endpoint info, config, contacts
        """
        endpoint_info = self._get("/api/endpoint/v1/endpoint")
        return {
            "endpoint": endpoint_info,
            "config": self.get_config(),
            "contacts": self.get_contacts(),
        }

    # ==================== MQTT Implementation ====================
    
    def _on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        """Callback when MQTT connection is established (paho-mqtt 2.0 compatible)"""
        if rc == 0:
            _LOGGER.info("MQTT connected successfully")
            self._mqtt_connected = True
            
            # Topics to subscribe based on Android app analysis:
            # - {deviceId}/state - Device state (ONLINE/OFFLINE)
            # - {deviceId}/tiles/{tileId}/state - Tile state updates
            # - {deviceId}/tiles/{tileId}/action - Tile actions
            # - {peerId}/# - Peer (door station) events
            # - {endpointId}/# - Endpoint events
            
            topics_to_subscribe = []
            
            # Device ID topics (from config.deviceId)
            if hasattr(self, '_device_id') and self._device_id:
                topics_to_subscribe.append(f"{self._device_id}/#")
                topics_to_subscribe.append(f"{self._device_id}/state")
                topics_to_subscribe.append(f"{self._device_id}/+/state")
                topics_to_subscribe.append(f"{self._device_id}/+/action")
            
            # Peer ID topics (door station)
            if hasattr(self, '_peer_id') and self._peer_id:
                topics_to_subscribe.append(f"{self._peer_id}/#")
            
            # Endpoint ID topics (our app instance)
            if self._endpoint_id:
                topics_to_subscribe.append(f"{self._endpoint_id}/#")
            
            # Also try common event patterns
            topics_to_subscribe.extend([
                "+/call",
                "+/ring",
                "+/doorbell",
                "+/event",
                "call/#",
                "ring/#",
                "doorbell/#",
            ])
            
            # Subscribe to all topics
            for topic in topics_to_subscribe:
                try:
                    result = client.subscribe(topic)
                    _LOGGER.info(f"Subscribed to '{topic}': result={result}")
                except Exception as e:
                    _LOGGER.warning(f"Failed to subscribe to '{topic}': {e}")
            
            # Also subscribe to all topics as fallback (for discovery)
            result_all = client.subscribe("#")
            _LOGGER.info(f"Subscribed to all topics '#': result={result_all}")
        else:
            _LOGGER.error(f"MQTT connection failed with code {rc}")
            self._mqtt_connected = False
    
    def _on_mqtt_disconnect(self, client, userdata, rc, properties=None):
        """Callback when MQTT connection is lost (paho-mqtt 2.0 compatible)"""
        _LOGGER.warning(f"MQTT disconnected with code {rc}")
        self._mqtt_connected = False
    
    def _on_mqtt_message(self, client, userdata, msg):
        """Callback when MQTT message is received"""
        _LOGGER.info(f"MQTT message received on topic '{msg.topic}': {msg.payload}")
        
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            
            # Call all registered callbacks
            for callback in self._mqtt_callbacks:
                try:
                    callback(msg.topic, payload)
                except Exception as e:
                    _LOGGER.error(f"Error in MQTT callback: {e}")
            
        except json.JSONDecodeError:
            _LOGGER.warning(f"Non-JSON MQTT message: {msg.payload}")
    
    def connect_mqtt(self, on_message_callback=None):
        """
        Connect to Siedle MQTT broker for real-time events
        
        Args:
            on_message_callback: Optional callback function(topic, payload)
            
        Returns:
            True if connection successful
        """
        if mqtt is None:
            _LOGGER.error("paho-mqtt not installed. Install with: pip install paho-mqtt")
            return False
        
        if self._mqtt_client is not None:
            _LOGGER.warning("MQTT already connected")
            return True
        
        # Get MQTT credentials
        mqtt_config = self.get_mqtt_credentials()
        if not mqtt_config:
            _LOGGER.error("MQTT credentials not available")
            return False
        
        _LOGGER.info(f"Connecting to MQTT broker {mqtt_config['host']}:{mqtt_config['port']}...")
        
        # Create MQTT client
        self._mqtt_client = mqtt.Client(
            client_id=mqtt_config['clientId'],
            clean_session=True
        )
        
        # Set username/password
        self._mqtt_client.username_pw_set(
            mqtt_config['username'],
            mqtt_config['password']
        )
        
        # Enable TLS/SSL
        if mqtt_config['protocol'] == 'ssl':
            self._mqtt_client.tls_set(
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2
            )
        
        # Set callbacks
        self._mqtt_client.on_connect = self._on_mqtt_connect
        self._mqtt_client.on_disconnect = self._on_mqtt_disconnect
        self._mqtt_client.on_message = self._on_mqtt_message
        
        # Register user callback if provided
        if on_message_callback:
            self._mqtt_callbacks.append(on_message_callback)
        
        try:
            # Connect to broker
            self._mqtt_client.connect(
                mqtt_config['host'],
                mqtt_config['port'],
                keepalive=60
            )
            
            # Start network loop in background thread
            self._mqtt_client.loop_start()
            
            # Wait for connection
            timeout = 10
            start_time = time.time()
            while not self._mqtt_connected and (time.time() - start_time) < timeout:
                time.sleep(0.1)
            
            if self._mqtt_connected:
                _LOGGER.info("MQTT connection established")
                return True
            else:
                _LOGGER.error("MQTT connection timeout")
                return False
                
        except Exception as e:
            _LOGGER.error(f"Failed to connect to MQTT: {e}")
            return False
    
    def disconnect_mqtt(self):
        """Disconnect from MQTT broker"""
        if self._mqtt_client:
            self._mqtt_client.loop_stop()
            self._mqtt_client.disconnect()
            self._mqtt_client = None
            self._mqtt_connected = False
            _LOGGER.info("MQTT disconnected")
    
    def add_mqtt_callback(self, callback):
        """
        Add callback for MQTT messages
        
        Args:
            callback: Function(topic, payload) to call on message
        """
        if callback not in self._mqtt_callbacks:
            self._mqtt_callbacks.append(callback)
    
    def remove_mqtt_callback(self, callback):
        """Remove MQTT callback"""
        if callback in self._mqtt_callbacks:
            self._mqtt_callbacks.remove(callback)
    
    @property
    def mqtt_connected(self):
        """Check if MQTT is connected"""
        return self._mqtt_connected

    # ==================== Push Notifications (FCM) ====================
    
    # Firebase/GCM credentials for Siedle app
    FCM_SENDER_ID = "787565799744"
    FCM_PROJECT_ID = "siedle-sus-android"
    FCM_APP_ID = "1:787565799744:android:37bf5f6305205a39"
    
    def __init_fcm_state(self):
        """Initialize FCM state variables"""
        if not hasattr(self, '_fcm_credentials'):
            self._fcm_credentials = None
            self._fcm_thread = None
            self._fcm_running = False
            self._fcm_callbacks = []
            self._processed_notification_ids = set()
    
    def register_fcm_push(self, credentials_file=None):
        """
        Register with FCM to receive push notifications.
        
        This creates a new FCM registration and registers the token with Siedle.
        Credentials are stored for later use.
        
        Args:
            credentials_file: Optional path to store/load FCM credentials
            
        Returns:
            FCM credentials dict if successful, None otherwise
        """
        self.__init_fcm_state()
        
        if not PUSH_RECEIVER_AVAILABLE or register is None:
            _LOGGER.error("push_receiver not available (protobuf compatibility issue)")
            return None
        
        # Try to load existing credentials
        if credentials_file and os.path.exists(credentials_file):
            try:
                with open(credentials_file, 'r') as f:
                    self._fcm_credentials = json.load(f)
                    _LOGGER.info("Loaded existing FCM credentials")
                    return self._fcm_credentials
            except Exception as e:
                _LOGGER.warning(f"Failed to load FCM credentials: {e}")
        
        # Register new credentials with FCM
        _LOGGER.info(f"Registering with FCM (sender_id={self.FCM_SENDER_ID})...")
        try:
            credentials = register(sender_id=self.FCM_SENDER_ID)
            self._fcm_credentials = credentials
            
            # Save credentials
            if credentials_file:
                with open(credentials_file, 'w') as f:
                    json.dump(credentials, f)
                _LOGGER.info(f"Saved FCM credentials to {credentials_file}")
            
            # Register push token with Siedle
            fcm_token = credentials.get('fcm', {}).get('token')
            if fcm_token:
                self._register_push_token(fcm_token)
            
            return credentials
            
        except Exception as e:
            _LOGGER.error(f"Failed to register with FCM: {e}")
            return None
    
    def _register_push_token(self, push_token):
        """Register FCM push token with Siedle API"""
        _LOGGER.info("Registering push token with Siedle...")
        
        data = {
            "notificationType": NOTIFICATIONTYPE,
            "tokenType": TOKENTYPE,
            "s_name": S_NAME,
            "pushToken": push_token
        }
        
        try:
            response = self._put("/api/endpoint/v1/endpoint/data", data)
            _LOGGER.info(f"Push token registered successfully: {response}")
            return response
        except Exception as e:
            _LOGGER.error(f"Failed to register push token: {e}")
            return None
    
    def start_fcm_listener(self, on_notification_callback=None, credentials_file=None):
        """
        Start listening for FCM push notifications in a background thread.
        
        Args:
            on_notification_callback: Function(notification_type, data) called on events
            credentials_file: Path to FCM credentials file
            
        Returns:
            True if started successfully
        """
        self.__init_fcm_state()
        
        if not PUSH_RECEIVER_AVAILABLE or listen is None:
            _LOGGER.warning("FCM push receiver not available (protobuf compatibility issue). Doorbell notifications will not work.")
            return False
        
        # Register if not already done
        if not self._fcm_credentials:
            self._fcm_credentials = self.register_fcm_push(credentials_file)
            if not self._fcm_credentials:
                return False
        
        # Add callback
        if on_notification_callback:
            self._fcm_callbacks.append(on_notification_callback)
        
        # Start listener thread
        if self._fcm_thread and self._fcm_thread.is_alive():
            _LOGGER.warning("FCM listener already running")
            return True
        
        import threading
        self._fcm_running = True
        self._fcm_thread = threading.Thread(target=self._fcm_listen_loop, daemon=True)
        self._fcm_thread.start()
        
        _LOGGER.info("FCM listener started")
        return True
    
    def _fcm_listen_loop(self):
        """Background thread that listens for FCM notifications"""
        from push_receiver import listen
        
        _LOGGER.info("FCM listen loop starting...")
        
        try:
            for obj, notification, data_message in listen(self._fcm_credentials):
                if not self._fcm_running:
                    break
                    
                self._handle_fcm_notification(obj, notification, data_message)
                
        except Exception as e:
            _LOGGER.error(f"FCM listener error: {e}")
        finally:
            _LOGGER.info("FCM listen loop ended")
    
    def _handle_fcm_notification(self, obj, notification, data_message):
        """Handle incoming FCM notification"""
        try:
            # Check for duplicate
            persistent_id = getattr(data_message, 'persistent_id', None)
            if persistent_id:
                if persistent_id in self._processed_notification_ids:
                    return
                self._processed_notification_ids.add(persistent_id)
                # Keep set from growing too large
                if len(self._processed_notification_ids) > 1000:
                    self._processed_notification_ids = set(list(self._processed_notification_ids)[-500:])
            
            _LOGGER.info(f"FCM notification received: {notification}")
            
            # Parse notification
            notification_type = "unknown"
            data = {}
            
            if notification:
                n = notification.get("notification", {})
                title = n.get("title", "")
                body = n.get("body", "")
                
                # Detect notification type
                if "klingel" in title.lower() or "doorbell" in title.lower() or "ring" in title.lower():
                    notification_type = "doorbell"
                elif "tür" in title.lower() or "door" in title.lower():
                    notification_type = "door"
                elif "anruf" in title.lower() or "call" in title.lower():
                    notification_type = "call"
                
                data = {
                    "title": title,
                    "body": body,
                    "raw": notification
                }
                
                _LOGGER.info(f"FCM event: type={notification_type}, title={title}, body={body}")
            
            # Call registered callbacks
            for callback in self._fcm_callbacks:
                try:
                    callback(notification_type, data)
                except Exception as e:
                    _LOGGER.error(f"Error in FCM callback: {e}")
                    
        except Exception as e:
            _LOGGER.error(f"Error handling FCM notification: {e}")
    
    def stop_fcm_listener(self):
        """Stop the FCM listener"""
        self.__init_fcm_state()
        self._fcm_running = False
        _LOGGER.info("FCM listener stopped")
    
    def add_fcm_callback(self, callback):
        """Add a callback for FCM notifications"""
        self.__init_fcm_state()
        if callback not in self._fcm_callbacks:
            self._fcm_callbacks.append(callback)
    
    def remove_fcm_callback(self, callback):
        """Remove an FCM callback"""
        self.__init_fcm_state()
        if callback in self._fcm_callbacks:
            self._fcm_callbacks.remove(callback)

    # ==================== SIP Listener for Doorbell Detection ====================
    
    def __init_sip_state(self):
        """Initialize SIP state variables"""
        if not hasattr(self, '_sip_socket'):
            self._sip_socket = None
            self._sip_thread = None
            self._sip_running = False
            self._sip_registered = False
            self._sip_callbacks = []
            self._sip_call_id = str(uuid.uuid4())
            self._sip_cseq = 0
            self._sip_realm = None
            self._sip_nonce = None
    
    def _get_local_ip(self) -> str:
        """Get local IP address for SIP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.100"
    
    def _compute_sip_digest(self, method: str, uri: str, realm: str, nonce: str, 
                           username: str, password: str) -> str:
        """Compute SIP Digest Authentication response"""
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return response
    
    def _create_sip_register(self, sip_config: dict, with_auth: bool = False) -> bytes:
        """Create SIP REGISTER message"""
        self.__init_sip_state()
        self._sip_cseq += 1
        
        local_ip = self._get_local_ip()
        local_port = 5060
        username = sip_config['username']
        host = sip_config['host']
        uri = f"sip:{host}"
        call_id = self._sip_call_id
        branch = uuid.uuid4().hex[:8]
        tag = uuid.uuid4().hex[:8]
        
        lines = [
            f"REGISTER {uri} SIP/2.0",
            f"Via: SIP/2.0/TLS {local_ip}:{local_port};rport;branch=z9hG4bK-{branch}",
            "Max-Forwards: 70",
            f"From: <sip:{username}@{host}>;tag={tag}",
            f"To: <sip:{username}@{host}>",
            f"Call-ID: {call_id}@{local_ip}",
            f"CSeq: {self._sip_cseq} REGISTER",
            f"Contact: <sip:{username}@{local_ip}:{local_port};transport=TLS>",
            "User-Agent: Siedle-HA/1.0",
            "Expires: 3600",
            "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE",
        ]
        
        if with_auth and self._sip_realm and self._sip_nonce:
            response = self._compute_sip_digest(
                method="REGISTER",
                uri=uri,
                realm=self._sip_realm,
                nonce=self._sip_nonce,
                username=username,
                password=sip_config['password']
            )
            lines.append(
                f'Authorization: Digest username="{username}", '
                f'realm="{self._sip_realm}", '
                f'nonce="{self._sip_nonce}", '
                f'uri="{uri}", '
                f'response="{response}", '
                f'algorithm=MD5'
            )
        
        lines.append("Content-Length: 0")
        lines.append("")
        lines.append("")
        
        return "\r\n".join(lines).encode('utf-8')
    
    def _parse_sip_response(self, data: bytes) -> dict:
        """Parse SIP response/request"""
        try:
            text = data.decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            
            result = {
                "raw": text,
                "status_line": lines[0] if lines else "",
                "status_code": 0,
                "method": None,
                "headers": {},
            }
            
            if lines and lines[0].startswith("SIP/2.0"):
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    result["status_code"] = int(parts[1])
            elif lines:
                parts = lines[0].split(" ")
                result["method"] = parts[0]
            
            for line in lines[1:]:
                if line == "":
                    break
                if ":" in line:
                    name, value = line.split(":", 1)
                    result["headers"][name.strip()] = value.strip()
            
            return result
        except Exception as e:
            _LOGGER.error(f"Error parsing SIP: {e}")
            return {"error": str(e)}
    
    def start_sip_listener(self, on_doorbell_callback=None):
        """
        Start SIP listener for doorbell detection.
        
        This registers with the Siedle SIP server and listens for
        incoming INVITE messages which indicate doorbell rings.
        
        Args:
            on_doorbell_callback: Function(event_type, data) called on doorbell
            
        Returns:
            True if started successfully
        """
        self.__init_sip_state()
        
        sip_config = self.get_sip_credentials()
        if not sip_config:
            _LOGGER.error("SIP credentials not available")
            return False
        
        if on_doorbell_callback:
            self._sip_callbacks.append(on_doorbell_callback)
        
        if self._sip_thread and self._sip_thread.is_alive():
            _LOGGER.warning("SIP listener already running")
            return True
        
        self._sip_running = True
        self._sip_thread = threading.Thread(
            target=self._sip_listen_loop,
            args=(sip_config,),
            daemon=True
        )
        self._sip_thread.start()
        
        _LOGGER.info("SIP listener started")
        return True
    
    def _sip_listen_loop(self, sip_config: dict):
        """Background thread for SIP listening"""
        try:
            # Connect with TLS
            _LOGGER.info(f"SIP: Connecting to {sip_config['host']}:{sip_config['port']}...")
            
            context = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            
            self._sip_socket = context.wrap_socket(
                sock,
                server_hostname=sip_config['host']
            )
            self._sip_socket.connect((sip_config['host'], sip_config['port']))
            
            _LOGGER.info("SIP: TLS connection established")
            
            # Initial REGISTER (get 401 challenge)
            register_msg = self._create_sip_register(sip_config, with_auth=False)
            self._sip_socket.send(register_msg)
            
            response = self._sip_socket.recv(4096)
            parsed = self._parse_sip_response(response)
            
            if parsed.get("status_code") == 401:
                # Extract auth params
                www_auth = parsed.get("headers", {}).get("WWW-Authenticate", "")
                realm_match = re.search(r'realm="([^"]+)"', www_auth)
                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                
                if realm_match and nonce_match:
                    self._sip_realm = realm_match.group(1)
                    self._sip_nonce = nonce_match.group(1)
                    
                    # Authenticated REGISTER
                    auth_register = self._create_sip_register(sip_config, with_auth=True)
                    self._sip_socket.send(auth_register)
                    
                    response = self._sip_socket.recv(4096)
                    parsed = self._parse_sip_response(response)
                    
                    if parsed.get("status_code") == 200:
                        _LOGGER.info("SIP: Registration successful!")
                        self._sip_registered = True
                    else:
                        _LOGGER.error(f"SIP: Registration failed: {parsed.get('status_line')}")
                        return
            elif parsed.get("status_code") == 200:
                _LOGGER.info("SIP: Registration successful (no auth needed)")
                self._sip_registered = True
            else:
                _LOGGER.error(f"SIP: Unexpected response: {parsed.get('status_line')}")
                return
            
            # Set non-blocking for listening
            self._sip_socket.setblocking(False)
            
            _LOGGER.info("SIP: Listening for incoming calls (doorbell)...")
            
            # Listen loop
            while self._sip_running:
                try:
                    data = self._sip_socket.recv(4096)
                    if data:
                        parsed = self._parse_sip_response(data)
                        method = parsed.get("method")
                        
                        if method == "INVITE":
                            _LOGGER.warning("🔔 SIP INVITE received - DOORBELL!")
                            
                            # Extract call info
                            from_header = parsed.get("headers", {}).get("From", "")
                            call_id = parsed.get("headers", {}).get("Call-ID", "")
                            
                            # Notify callbacks
                            for callback in self._sip_callbacks:
                                try:
                                    callback("doorbell", {
                                        "source": "sip",
                                        "from": from_header,
                                        "call_id": call_id,
                                    })
                                except Exception as e:
                                    _LOGGER.error(f"SIP callback error: {e}")
                        
                        elif method:
                            _LOGGER.debug(f"SIP: Received {method}")
                
                except ssl.SSLWantReadError:
                    pass
                except BlockingIOError:
                    pass
                except Exception as e:
                    if self._sip_running:
                        _LOGGER.debug(f"SIP receive error: {e}")
                
                time.sleep(0.1)
                
        except Exception as e:
            _LOGGER.error(f"SIP listener error: {e}")
        finally:
            if self._sip_socket:
                try:
                    self._sip_socket.close()
                except:
                    pass
            self._sip_socket = None
            self._sip_registered = False
            _LOGGER.info("SIP listener stopped")
    
    def stop_sip_listener(self):
        """Stop the SIP listener"""
        self.__init_sip_state()
        self._sip_running = False
        if self._sip_socket:
            try:
                self._sip_socket.close()
            except:
                pass
        _LOGGER.info("SIP listener stop requested")
    
    def add_sip_callback(self, callback):
        """Add callback for SIP doorbell events"""
        self.__init_sip_state()
        if callback not in self._sip_callbacks:
            self._sip_callbacks.append(callback)
    
    def remove_sip_callback(self, callback):
        """Remove SIP callback"""
        self.__init_sip_state()
        if callback in self._sip_callbacks:
            self._sip_callbacks.remove(callback)
    
    @property
    def sip_registered(self):
        """Check if SIP is registered"""
        return getattr(self, '_sip_registered', False)