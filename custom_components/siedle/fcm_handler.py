"""
FCM Handler for Siedle Doorbell Detection
Manages Firebase Cloud Messaging connection for receiving doorbell notifications.
"""

import asyncio
import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN, SIGNAL_SIEDLE_CONNECTION_UPDATE

_LOGGER = logging.getLogger(__name__)

# Watchdog timings.
#
# The real fault signal is the library's connection status, not silence: a
# doorbell nobody rings produces no FCM traffic for hours, which is perfectly
# healthy. A 30 minute silence timeout therefore tore down working connections
# several times a night, and every reconnect re-registers the push token with
# Siedle — needless load, and a chance to end up unregistered.
#
# Silence is kept only as a last-resort self-heal for a listener that hangs
# while still claiming to be connected. Once a day is enough for that.
FCM_WATCHDOG_INTERVAL = 120
FCM_STALE_TIMEOUT = 86400
FCM_RECONNECT_MAX_DELAY = 900

SIEDLE_FIREBASE = {
    "project_id": "siedle-sus-android",
    "api_key": "AIzaSyDBeZC0fOq0b3WHZBUzvU2FM5nrLgglFQw",
    "app_id": "1:787565799744:android:37bf5f6305205a39",
    "sender_id": "787565799744",
}

# Siedle API for FCM registration
SIEDLE_FCM_ENDPOINT = "https://sus2.siedle.com/sus2/api/endpoint/v1/endpoint/data"


class SiedleFCMHandler:
    """
    Handles Firebase Cloud Messaging for Siedle doorbell notifications.
    
    This class:
    - Registers with Firebase to get an FCM token
    - Registers the FCM token with Siedle's server
    - Maintains a persistent connection to receive push notifications
    - Fires Home Assistant events when a doorbell ring is detected
    """
    
    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        access_token: str,
        shared_secret: Optional[bytes] = None,
        device_name: str = "Home Assistant",
        fcm_credentials_file: Optional[str] = None,
        token_provider: Optional[Callable[[], Optional[str]]] = None,
    ):
        """Initialize the FCM handler."""
        self._hass = hass
        self._entry_id = entry_id
        self._access_token = access_token
        # Siedle rotates the OAuth access token, so the copy handed in at setup
        # goes stale. Re-registering with it failed with 401 invalid_token and
        # left the push registration broken. The provider fetches the current
        # token at call time instead.
        self._token_provider = token_provider
        self._shared_secret = shared_secret
        self._device_name = device_name
        self._fcm_credentials_file = fcm_credentials_file or hass.config.path(
            ".storage", f"siedle_fcm_{entry_id}.json"
        )
        
        self._client = None
        self._fcm_token = None
        self._running = False
        self._connected = False
        self._thread = None
        self._stop_event = threading.Event()

        # Watchdog: the FCM connection can die silently — the listener thread
        # ends, or the client stops delivering while still claiming to be
        # connected. Without this, users had to toggle FCM off and on by hand.
        self._watchdog_unsub = None
        self._last_activity = 0.0
        self._reconnect_failures = 0
        self._saw_disconnected = False

        # Last call info for deduplication
        self._last_call_id = None
        self._last_call_time = None
    
    @property
    def is_connected(self) -> bool:
        """Return True if FCM connection is active.

        Do NOT infer this from our listener thread: start_listening() returns
        as soon as the library has taken over in its own thread, so our thread
        finishing is the normal case, not a failure.
        """
        return self._connected
    
    @property
    def fcm_token(self) -> Optional[str]:
        """Return the FCM token."""
        return self._fcm_token
    
    async def async_start(self) -> bool:
        """Start the FCM listener in a background thread."""
        if self._running:
            _LOGGER.warning("FCM handler already running")
            return True
        
        try:
            # Import FCM client from pip package fcm-receiver
            from fcm_receiver import FCMClient
        except ImportError as e:
            _LOGGER.error(f"Failed to import FCM receiver: {e}")
            _LOGGER.error("Install with: pip install fcm-receiver")
            return False
        
        # Check for http_ece (required for message decryption)
        try:
            import http_ece
        except ImportError:
            _LOGGER.warning(
                "http_ece not installed - FCM messages cannot be decrypted. "
                "Install with: pip install http_ece"
            )
        
        # Setup FCM client
        self._client = FCMClient()
        self._client.project_id = SIEDLE_FIREBASE["project_id"]
        self._client.api_key = SIEDLE_FIREBASE["api_key"]
        self._client.app_id = SIEDLE_FIREBASE["app_id"]
        
        # Load or create FCM credentials
        success = await self._hass.async_add_executor_job(
            self._load_or_create_credentials
        )
        
        if not success:
            _LOGGER.error("Failed to setup FCM credentials")
            return False
        
        # Register FCM token with Siedle
        registered = await self._hass.async_add_executor_job(
            self._register_with_siedle
        )
        
        if not registered:
            _LOGGER.warning("Failed to register FCM token with Siedle - doorbell detection may not work")
        
        # Start listener thread
        self._stop_event.clear()
        self._running = True
        _LOGGER.info("Creating FCM listener thread...")
        self._thread = threading.Thread(
            target=self._listener_thread,
            name=f"siedle_fcm_{self._entry_id}",
            daemon=True
        )
        self._thread.start()
        _LOGGER.debug("FCM listener thread started: %s", self._thread.name)
        
        self._last_activity = time.time()
        self._schedule_watchdog()

        _LOGGER.info("Siedle FCM handler started")
        return True

    def _schedule_watchdog(self, delay: Optional[float] = None) -> None:
        """Arm the next watchdog check."""
        self._cancel_watchdog()
        self._watchdog_unsub = async_call_later(
            self._hass,
            FCM_WATCHDOG_INTERVAL if delay is None else delay,
            self._async_watchdog,
        )

    def _cancel_watchdog(self) -> None:
        if self._watchdog_unsub is not None:
            self._watchdog_unsub()
            self._watchdog_unsub = None

    async def _async_watchdog(self, _now=None) -> None:
        """Reconnect when the listener died or went quiet."""
        self._watchdog_unsub = None
        if not self._running:
            return

        # Liveness comes from the library's own status callback and from the
        # traffic we see — never from our listener thread, which finishes as
        # soon as the library takes over internally.
        idle_for = time.time() - self._last_activity
        stale = idle_for > FCM_STALE_TIMEOUT
        # One isolated "disconnected" is normal around startup or a brief
        # network blip; only a state that survives two checks counts.
        disconnected = not self._connected
        persistent_disconnect = disconnected and self._saw_disconnected

        self._saw_disconnected = disconnected

        if not (persistent_disconnect or stale):
            self._reconnect_failures = 0
            self._schedule_watchdog()
            return

        reason = (
            f"still disconnected after {int(FCM_WATCHDOG_INTERVAL)}s"
            if persistent_disconnect
            else f"no FCM traffic for {int(idle_for)}s"
        )
        _LOGGER.warning("FCM watchdog: %s — reconnecting", reason)

        try:
            await self.async_stop()
            started = await self.async_start()
        except Exception as err:  # noqa: BLE001 - must never kill the watchdog
            _LOGGER.error("FCM watchdog: reconnect failed: %s", err)
            started = False

        if started:
            self._reconnect_failures = 0
            return  # async_start armed the watchdog again

        # Back off so a permanently unreachable service is not hammered.
        self._reconnect_failures += 1
        self._running = True  # keep the watchdog alive for the next attempt
        delay = min(
            FCM_WATCHDOG_INTERVAL * (2 ** min(self._reconnect_failures, 5)),
            FCM_RECONNECT_MAX_DELAY,
        )
        _LOGGER.warning(
            "FCM watchdog: reconnect attempt %d failed, retrying in %ds",
            self._reconnect_failures, delay,
        )
        self._schedule_watchdog(delay)

    async def async_stop(self):
        """Stop the FCM listener."""
        self._cancel_watchdog()
        if not self._running:
            return

        _LOGGER.info("Stopping Siedle FCM handler...")
        self._running = False
        self._stop_event.set()
        
        # Stop FCM client - method is close() not stop()
        if self._client:
            try:
                self._client.close()
            except Exception as e:
                _LOGGER.debug(f"Error closing FCM client: {e}")
        
        # Wait for thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        
        self._connected = False
        _LOGGER.info("Siedle FCM handler stopped")
    
    def _load_or_create_credentials(self) -> bool:
        """Load existing FCM credentials or create new ones."""
        try:
            if os.path.exists(self._fcm_credentials_file):
                _LOGGER.debug("Loading FCM credentials from %s", self._fcm_credentials_file)
                with open(self._fcm_credentials_file, 'r') as f:
                    creds = json.load(f)
                
                self._client.android_id = creds["android_id"]
                self._client.security_token = creds["security_token"]
                self._client.gcm_token = creds.get("gcm_token", "")
                # For Android, GCM token IS the FCM token
                self._client.fcm_token = creds.get("gcm_token", "")
                self._fcm_token = self._client.fcm_token
                
                # Load keys
                if "private_key_b64" in creds and "auth_secret_b64" in creds:
                    self._client.load_keys(
                        creds["private_key_b64"],
                        creds["auth_secret_b64"]
                    )
                else:
                    self._client.create_new_keys()
                
                _LOGGER.debug("FCM credentials loaded, token: %s...", self._fcm_token[:20])
                return True
            
            # Create new registration using Android-style registration
            # The fcm_receiver library's register() tries to do Web Push registration
            # which fails with HTTP 500. For Android, we only need GCM token.
            _LOGGER.info("Creating new FCM registration (Android mode)...")
            _LOGGER.info("Creating FCM keys...")
            priv_b64, auth_b64 = self._client.create_new_keys()
            _LOGGER.info("FCM keys created")
            
            # Do Android-style registration manually
            try:
                android_id, security_token, gcm_token = self._register_android_fcm()
                _LOGGER.debug("Android FCM registration complete: android_id=%s", android_id)
            except Exception as reg_err:
                _LOGGER.error(f"Android FCM registration failed: {reg_err}")
                import traceback
                _LOGGER.error(traceback.format_exc())
                raise
            
            # For Android, GCM token IS the FCM token
            self._fcm_token = gcm_token
            self._client.android_id = android_id
            self._client.security_token = security_token
            self._client.gcm_token = gcm_token
            self._client.fcm_token = gcm_token
            
            # Save credentials
            creds = {
                "android_id": android_id,
                "security_token": security_token,
                "gcm_token": gcm_token,
                "fcm_token": gcm_token,  # Same as gcm_token for Android
                "private_key_b64": priv_b64,
                "auth_secret_b64": auth_b64,
            }
            
            fd = os.open(self._fcm_credentials_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(creds, f, indent=2)
            
            _LOGGER.info("FCM registration successful")
            return True
            
        except Exception as e:
            _LOGGER.error(f"Failed to setup FCM credentials: {e}")
            return False
    
    def _register_android_fcm(self) -> tuple:
        """
        Register with Firebase using Android-style registration.
        
        The fcm_receiver library's register() method tries Web Push registration
        (via fcmregistrations.googleapis.com) which fails with HTTP 500 for Android apps.
        
        For Android FCM, we only need:
        1. GCM Checkin (get android_id, security_token)
        2. GCM Register (get gcm_token)
        
        The GCM token IS the FCM token for Android - no separate FCM registration needed.
        
        Returns: (android_id, security_token, gcm_token)
        """
        from fcm_receiver.http_client import (
            send_gcm_checkin_request,
            send_gcm_register_request,
            send_fcm_install_request,
        )
        from fcm_receiver.messages_manual import (
            AndroidCheckinRequest,
            AndroidCheckinProto,
            ChromeBuildProto,
        )
        
        # Step 1: GCM Checkin
        _LOGGER.info("Step 1: GCM Checkin...")
        chrome_build = ChromeBuildProto(platform=3, chrome_version="63.0.3234.0", channel=1)
        checkin = AndroidCheckinProto(type=3, chrome_build=chrome_build)
        checkin_req = AndroidCheckinRequest(
            user_serial_number=0,
            checkin=checkin,
            version=3,
        )
        android_id, security_token = send_gcm_checkin_request(checkin_req)
        _LOGGER.info(f"GCM Checkin OK: android_id={android_id}")
        
        # Step 2: Get Installation Auth Token (needed for GCM register with Android app)
        _LOGGER.info("Step 2: Firebase Installation...")
        installation_token = send_fcm_install_request(
            api_key=SIEDLE_FIREBASE["api_key"],
            project_id=SIEDLE_FIREBASE["project_id"],
            app_id=SIEDLE_FIREBASE["app_id"],
            android=True,  # Important: use Android mode
        )
        _LOGGER.info("Firebase Installation OK")
        
        # Step 3: GCM Register with Android app credentials
        _LOGGER.info("Step 3: GCM Register (Android)...")
        
        # Android app info from APK
        android_app = {
            "android_package": "de.siedle.app.sus2.android",
            "android_package_cert": "5dbeff74f9dc0cd0c9d0c27e6e8c15fbc3ba0b0f",  # SHA1 fingerprint lowercase
            "gcm_sender_id": SIEDLE_FIREBASE["sender_id"],
        }
        
        # Google's GCM register frequently returns a transient
        # PHONE_REGISTRATION_ERROR right after check-in because the freshly
        # minted android_id needs a few seconds to propagate on Google's
        # backend. The official push_receiver/firebase-messaging clients retry
        # this call; upstream fcm_receiver does not, so we retry here.
        # Runs in an executor thread (via async_add_executor_job), so the
        # blocking sleep does not stall the event loop.
        max_attempts = 5
        retry_delay = 5
        last_err = None
        for attempt in range(1, max_attempts + 1):
            try:
                gcm_token = send_gcm_register_request(
                    android_id=android_id,
                    security_token=security_token,
                    app_id=SIEDLE_FIREBASE["app_id"],
                    android_app=android_app,
                    installation_auth_token=installation_token,
                )
                _LOGGER.info(f"GCM Register OK: token={gcm_token[:30]}...")
                return android_id, security_token, gcm_token
            except RuntimeError as e:
                last_err = e
                if "PHONE_REGISTRATION_ERROR" in str(e) and attempt < max_attempts:
                    _LOGGER.warning(
                        "GCM register attempt %d/%d failed (%s); retrying in %ds...",
                        attempt, max_attempts, e, retry_delay,
                    )
                    time.sleep(retry_delay)
                    continue
                raise

        # Should not be reachable (loop either returns or raises), but be safe.
        raise last_err
    
    def _encrypt_name(self, name: str) -> Optional[str]:
        """Encrypt device name using AES/CBC with shared secret.
        
        The Siedle app uses AES/CBC/PKCS5Padding with:
        - Key: sharedSecret (32 bytes)
        - IV: 16 zero bytes
        - Output: hex encoded
        """
        if not self._shared_secret:
            _LOGGER.warning("No shared secret available for name encryption")
            return name  # Fall back to plain text
        
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.backends import default_backend
            
            # IV is 16 zero bytes (from APK: CryptoCbc.java)
            iv = bytes(16)
            
            # Pad the name to AES block size (PKCS5/PKCS7)
            padder = padding.PKCS7(128).padder()
            name_bytes = name.encode('utf-8')
            padded_data = padder.update(name_bytes) + padder.finalize()
            
            # Encrypt with AES-CBC
            cipher = Cipher(
                algorithms.AES(self._shared_secret),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return as hex string
            return encrypted.hex()
            
        except Exception as e:
            _LOGGER.error(f"Failed to encrypt device name: {e}")
            return name  # Fall back to plain text
    
    def _register_with_siedle(self) -> bool:
        """Register FCM token with Siedle's server."""
        import requests
        
        if not self._fcm_token:
            _LOGGER.error("No FCM token available for Siedle registration")
            return False
        
        headers = {
            "Authorization": f"Bearer {self._current_access_token()}",
            "Content-Type": "application/json",
        }
        
        # Encrypt device name with shared secret (like Android app does)
        encrypted_name = self._encrypt_name(self._device_name)
        _LOGGER.debug(f"Device name '{self._device_name}' -> encrypted: {encrypted_name[:20] if encrypted_name else 'None'}...")
        
        # Payload format from APK analysis:
        # - notificationType: "WakeUp" (for background notifications)
        # - pushToken: FCM token
        # - s_name: Device name (AES encrypted, hex encoded)
        # - tokenType: "SUS_ANDROID" (from R.string.push_app_id)
        payload = {
            "notificationType": "WakeUp",
            "pushToken": self._fcm_token,
            "s_name": encrypted_name,
            "tokenType": "SUS_ANDROID",
        }
        
        try:
            response = requests.put(
                SIEDLE_FCM_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                _LOGGER.info("FCM token registered with Siedle successfully")
                return True
            else:
                _LOGGER.error(
                    f"Failed to register FCM token with Siedle: "
                    f"Status {response.status_code}, {response.text}"
                )
                return False
                
        except Exception as e:
            _LOGGER.error(f"Error registering FCM token with Siedle: {e}")
            return False
    
    def _listener_thread(self):
        """Background thread for FCM message reception."""
        _LOGGER.debug("FCM listener thread started")

        self._client.on_notification_message = self._on_notification
        self._client.on_data_message = self._on_data_message
        self._client.on_connection_status = self._on_connection_status

        try:
            self._client.start_listening()
            _LOGGER.debug("FCM start_listening() returned")
        except RuntimeError as e:
            _LOGGER.exception("FCM listener RuntimeError: %s", e)
        except Exception as e:
            if self._running:
                _LOGGER.exception("FCM listener error: %s", e)
        finally:
            self._connected = False
            _LOGGER.debug("FCM listener thread ended")
    
    def _on_connection_status(self, status: str, client_id: str):
        """Handle FCM connection status changes."""
        _LOGGER.debug(f"FCM connection status: {status}")
        self._last_activity = time.time()

        was_connected = self._connected
        self._connected = (status == "connected")
        
        if self._connected and not was_connected:
            _LOGGER.info("FCM connection established - doorbell detection active")
            self._fire_event("fcm_connected", {"status": "connected"})
            # Dispatch signal so binary sensor updates immediately
            self._hass.loop.call_soon_threadsafe(
                async_dispatcher_send, self._hass, SIGNAL_SIEDLE_CONNECTION_UPDATE
            )
        elif not self._connected and was_connected:
            _LOGGER.warning("FCM connection lost")
            self._fire_event("fcm_disconnected", {"status": "disconnected"})
            self._hass.loop.call_soon_threadsafe(
                async_dispatcher_send, self._hass, SIGNAL_SIEDLE_CONNECTION_UPDATE
            )
    
    def _on_notification(self, message: dict, client_id: str):
        """Handle FCM notification message."""
        self._last_activity = time.time()
        _LOGGER.debug("FCM notification received: %s", list(message.keys()) if isinstance(message, dict) else type(message).__name__)
        self._process_message(message)

    def _on_data_message(self, data: bytes, client_id: str):
        """Handle FCM data message."""
        self._last_activity = time.time()
        _LOGGER.debug("FCM data message received (%d bytes)", len(data) if data else 0)
        try:
            message = json.loads(data.decode())
            self._process_message({"payload": {"data": message}})
        except Exception as e:
            _LOGGER.warning(f"Failed to parse FCM data: {e}")
    
    def _process_message(self, message: dict):
        """Process incoming FCM message and fire events."""
        try:
            payload = message.get("payload", {})
            data = payload.get("data", {})
            
            msg_type = data.get("type", "").upper()
            call_id = data.get("tfcallid", "")
            timestamp = data.get("sustimestamp", "")
            
            _LOGGER.debug(f"Processing FCM message: type={msg_type}, call_id={call_id}")
            
            # Parse nested payload if present
            inner_payload = {}
            if "payload" in data and isinstance(data["payload"], str):
                try:
                    inner_payload = json.loads(data["payload"])
                except:
                    pass
            
            callee = inner_payload.get("callee") or data.get("callee", "")
            
            if msg_type == "CALL":
                # Deduplicate rapid-fire notifications
                if call_id == self._last_call_id:
                    _LOGGER.debug(f"Duplicate CALL notification ignored: {call_id}")
                    return
                
                self._last_call_id = call_id
                self._last_call_time = datetime.now()
                
                _LOGGER.info("DOORBELL RING DETECTED! Call ID: %s", call_id)
                
                # Fire doorbell event
                self._fire_event("doorbell", {
                    "call_id": call_id,
                    "callee": callee,
                    "timestamp": timestamp,
                    "type": "CALL",
                })
                
                # Also fire generic event
                self._fire_event("event", {
                    "type": "fcm",
                    "event_type": "doorbell",
                    "call_id": call_id,
                    "callee": callee,
                    "timestamp": timestamp,
                    "raw": data,
                })
                
            elif msg_type == "CANCEL_CALL":
                _LOGGER.info(f"Call ended: {call_id}")
                
                self._fire_event("call_ended", {
                    "call_id": call_id,
                    "timestamp": timestamp,
                    "type": "CANCEL_CALL",
                })
                
                # Clear last call
                if call_id == self._last_call_id:
                    self._last_call_id = None
                
            else:
                # Log unknown message types
                _LOGGER.debug(f"Unknown FCM message type: {msg_type}")
                self._fire_event("event", {
                    "type": "fcm",
                    "event_type": msg_type.lower() if msg_type else "unknown",
                    "raw": data,
                })
                
        except Exception as e:
            _LOGGER.error(f"Error processing FCM message: {e}")
    
    def _fire_event(self, event_name: str, data: Dict[str, Any]):
        """Fire a Home Assistant event."""
        event_data = {
            "entry_id": self._entry_id,
            **data,
        }
        
        # Schedule event fire on the event loop
        self._hass.loop.call_soon_threadsafe(
            self._hass.bus.async_fire,
            f"{DOMAIN}_{event_name}",
            event_data,
        )
    
    def _current_access_token(self) -> Optional[str]:
        """Return the token that is valid right now."""
        if self._token_provider is not None:
            try:
                token = self._token_provider()
                if token:
                    if token != self._access_token:
                        _LOGGER.debug("FCM: using refreshed Siedle access token")
                        self._access_token = token
                    return token
            except Exception as err:  # noqa: BLE001 - never block registration
                _LOGGER.debug("FCM: token provider failed (%s), using cached token", err)
        return self._access_token

    async def async_update_access_token(self, new_token: str):
        """Update the access token (after refresh)."""
        self._access_token = new_token
        
        # Re-register with Siedle using new token
        success = await self._hass.async_add_executor_job(
            self._register_with_siedle
        )
        
        if not success:
            _LOGGER.warning("Failed to re-register FCM token after token refresh")
