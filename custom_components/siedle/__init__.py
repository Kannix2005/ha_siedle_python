"""The Siedle integration."""
import asyncio
import logging
import os
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.components.http import HomeAssistantView
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DOMAIN,
    SERVICE_OPEN_DOOR,
    SERVICE_TOGGLE_LIGHT,
    SERVICE_HANGUP,
    ATTR_CONTACT_ID,
    CONF_EXT_SIP_ENABLED,
    CONF_EXT_SIP_HOST,
    CONF_EXT_SIP_PORT,
    CONF_EXT_SIP_USERNAME,
    CONF_EXT_SIP_PASSWORD,
    CONF_EXT_SIP_TRANSPORT,
    CONF_FORWARD_ENABLED,
    CONF_FORWARD_TO_NUMBER,
    CONF_FORWARD_FROM_NUMBER,
    CONF_AUTO_ANSWER,
    CONF_RECORDING_ENABLED,
    CONF_RECORDING_DURATION,
    CONF_RECORDING_PATH,
    DEFAULT_EXT_SIP_PORT,
    DEFAULT_EXT_SIP_TRANSPORT,
    DEFAULT_RECORDING_DURATION,
    DEFAULT_RECORDING_PATH,
    CONF_FCM_ENABLED,
    CONF_FCM_DEVICE_NAME,
    DEFAULT_FCM_DEVICE_NAME,
    SIGNAL_SIEDLE_CONNECTION_UPDATE,
    # F1: Forward timeout
    CONF_FORWARD_TIMEOUT,
    DEFAULT_FORWARD_TIMEOUT,
    # F2: Multi-target (uses CONF_FORWARD_TO_NUMBER)
    # F6: Schedule
    CONF_FORWARD_SCHEDULE_ENABLED,
    CONF_FORWARD_SCHEDULE_START,
    CONF_FORWARD_SCHEDULE_END,
    CONF_FORWARD_SCHEDULE_DAYS,
    DEFAULT_FORWARD_SCHEDULE_START,
    DEFAULT_FORWARD_SCHEDULE_END,
    DEFAULT_FORWARD_SCHEDULE_DAYS,
    # F7: Announcement
    CONF_ANNOUNCEMENT_ENABLED,
    CONF_ANNOUNCEMENT_FILE,
    DEFAULT_ANNOUNCEMENT_FILE,
    # F8: DTMF
    CONF_DTMF_ENABLED,
    CONF_DTMF_DOOR_CODE,
    CONF_DTMF_LIGHT_CODE,
    DEFAULT_DTMF_DOOR_CODE,
    DEFAULT_DTMF_LIGHT_CODE,
    # F12: Multi-button
    CONF_DOORBELL_BUTTONS,
    # F4: Call history
    CONF_CALL_HISTORY_SIZE,
    DEFAULT_CALL_HISTORY_SIZE,
    # F13: FritzBox
    CONF_FRITZBOX_ENABLED,
    CONF_FRITZBOX_HOST,
    CONF_FRITZBOX_USER,
    CONF_FRITZBOX_PASSWORD,
    CONF_FRITZBOX_PHONE_NUMBER,
    DEFAULT_FRITZBOX_HOST,
    DEFAULT_FRITZBOX_USER,
)
from .siedle_api import Siedle
from .fcm_handler import SiedleFCMHandler

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON, Platform.CAMERA]

# This integration is config entry only
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Siedle component."""
    hass.data.setdefault(DOMAIN, {})
    
    # Register QR callback and scanner API endpoints only once
    registered_names = {getattr(r, 'name', None) for r in hass.http.app.router._resources}
    
    if "api:siedle:qr_callback" not in registered_names:
        _LOGGER.info("Registering Siedle QR callback view at /api/siedle/qr_callback")
        hass.http.register_view(SiedleQRCallbackView())
    else:
        _LOGGER.debug("Siedle QR callback view already registered")
    
    if "api:siedle:qr_scanner" not in registered_names:
        _LOGGER.info("Registering Siedle QR scanner view at /api/siedle/qr_scanner")
        hass.http.register_view(SiedleQRScannerView())
    else:
        _LOGGER.debug("Siedle QR scanner view already registered")
    
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up Siedle from a config entry."""
    setup_info = entry.data.get("setup_info")
    token = entry.data.get("token")
    setup_data = entry.data.get("setup_data")
    shared_secret = entry.data.get("shared_secret")  # Decrypted secret (hex string)
    endpoint_id = entry.data.get("endpoint_id")
    transfer_secret = entry.data.get("transfer_secret")

    # Ensure Siedle data directory exists (for tokens, cache, etc.)
    siedle_data_dir = hass.config.path("siedle")
    os.makedirs(siedle_data_dir, exist_ok=True)

    # Migrate old token files from config root to siedle/ subfolder
    old_token_path = hass.config.path(f".siedle_token_{entry.entry_id}.json")
    new_token_path = os.path.join(siedle_data_dir, f"token_{entry.entry_id}.json")
    if os.path.exists(old_token_path) and not os.path.exists(new_token_path):
        try:
            os.rename(old_token_path, new_token_path)
            _LOGGER.info("Migrated token file to siedle/ subfolder")
        except OSError as e:
            _LOGGER.warning("Could not migrate token file: %s", e)

    # Initialize Siedle API
    try:
        # Use cached token if available, otherwise authorize
        if token and setup_data:
            _LOGGER.info("Using cached token from config entry")
            siedle = await hass.async_add_executor_job(
                lambda: Siedle(
                    token=token,
                    token_cache_file=new_token_path,
                )
            )
            # Restore setupData, endpoint_id, transferSecret, and DECRYPTED sharedSecret
            siedle._setupData = setup_data
            siedle._endpoint_id = endpoint_id
            siedle._transferSecret = transfer_secret
            # Restore decrypted sharedSecret (critical for door/light control!)
            if shared_secret:
                siedle._sharedSecret = bytes.fromhex(shared_secret)
                _LOGGER.info("Restored decrypted sharedSecret from config entry")
            else:
                _LOGGER.warning("No sharedSecret in config - door/light control may not work!")
            # Load config and contacts
            await hass.async_add_executor_job(siedle._load_config)
            await hass.async_add_executor_job(siedle._load_contacts)
        else:
            _LOGGER.info("No cached token, authorizing with setup info")
            siedle = await hass.async_add_executor_job(
                lambda: Siedle(
                    setupInfo=setup_info,
                    token_cache_file=new_token_path,
                )
            )
    except Exception as err:
        _LOGGER.error("Failed to setup Siedle: %s", err)
        raise ConfigEntryNotReady from err

    # Setup data coordinator
    coordinator = SiedleDataUpdateCoordinator(hass, siedle)
    await coordinator.async_config_entry_first_refresh()

    # Store coordinator
    hass.data[DOMAIN][entry.entry_id] = {
        "api": siedle,
        "coordinator": coordinator,
        "sip_manager": None,
        "rtp_bridge": None,
        "fcm_handler": None,
        "last_recording_sensor": None,
        "call_history_sensor": None,
        "fritzbox_dialer": None,
    }

    # ============== Setup SIP Call Manager ==============
    sip_manager = None
    rtp_bridge = None
    
    if entry.options.get("enable_sip", True):
        try:
            from .sip_manager import SipCallManager, SipConfig, SipTransport
            from .rtp_handler import RtpBridge
            
            # Get Siedle SIP credentials
            sip_creds = await hass.async_add_executor_job(siedle.get_sip_credentials)
            
            if sip_creds:
                # Log SIP credentials for debugging (obfuscate password)
                _LOGGER.info(f"SIP credentials loaded: host={sip_creds.get('host')}, "
                            f"port={sip_creds.get('port')}, "
                            f"username={sip_creds.get('username')}, "
                            f"protocol={sip_creds.get('protocol', 'unknown')}")
                siedle_sip_config = SipConfig.from_dict(sip_creds)
                
                # Check for external SIP configuration
                external_sip_config = None
                if entry.options.get(CONF_EXT_SIP_ENABLED, False):
                    ext_host = entry.options.get(CONF_EXT_SIP_HOST)
                    if ext_host:
                        transport_str = entry.options.get(CONF_EXT_SIP_TRANSPORT, DEFAULT_EXT_SIP_TRANSPORT)
                        external_sip_config = SipConfig(
                            host=ext_host,
                            port=entry.options.get(CONF_EXT_SIP_PORT, DEFAULT_EXT_SIP_PORT),
                            username=entry.options.get(CONF_EXT_SIP_USERNAME, ""),
                            password=entry.options.get(CONF_EXT_SIP_PASSWORD, ""),
                            transport=SipTransport(transport_str),
                            display_name="Siedle Türstation",
                        )
                        _LOGGER.info(f"External SIP configured: {ext_host}")
                
                # Get forwarding settings
                forward_enabled = entry.options.get(CONF_FORWARD_ENABLED, False)
                forward_to = entry.options.get(CONF_FORWARD_TO_NUMBER) if forward_enabled else None
                forward_from = entry.options.get(CONF_FORWARD_FROM_NUMBER) if forward_enabled else None
                
                # Auto-answer if explicitly enabled OR if recording is enabled (can't record without answering)
                recording_enabled = entry.options.get(CONF_RECORDING_ENABLED, False)
                auto_answer = entry.options.get(CONF_AUTO_ANSWER, False) or recording_enabled
                
                if recording_enabled and not entry.options.get(CONF_AUTO_ANSWER, False):
                    _LOGGER.info("Auto-answer enabled because recording is active")
                
                # Get recording settings
                recording_path = None
                recording_duration = None
                if recording_enabled:
                    base_path = entry.options.get(CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH)
                    recording_duration = entry.options.get(CONF_RECORDING_DURATION, DEFAULT_RECORDING_DURATION)
                    # Build full path
                    full_path = hass.config.path(base_path, "doorbell")
                    # Ensure directory exists
                    os.makedirs(full_path, exist_ok=True)
                    recording_path = os.path.join(full_path, "doorbell")
                    _LOGGER.info(f"Recording configured: path={recording_path}, duration={recording_duration}s")
                
                # Create SIP Call Manager
                sip_manager = SipCallManager(
                    siedle_config=siedle_sip_config,
                    external_config=external_sip_config,
                    forward_to_number=forward_to,
                    forward_from_number=forward_from,
                    auto_answer=auto_answer,
                    recording_enabled=recording_enabled,
                    recording_path=recording_path,
                    recording_duration=recording_duration,
                    # F1: Forward timeout
                    forward_timeout=entry.options.get(CONF_FORWARD_TIMEOUT, DEFAULT_FORWARD_TIMEOUT),
                    # F6: Schedule
                    forward_schedule_enabled=entry.options.get(CONF_FORWARD_SCHEDULE_ENABLED, False),
                    forward_schedule_start=entry.options.get(CONF_FORWARD_SCHEDULE_START, DEFAULT_FORWARD_SCHEDULE_START),
                    forward_schedule_end=entry.options.get(CONF_FORWARD_SCHEDULE_END, DEFAULT_FORWARD_SCHEDULE_END),
                    forward_schedule_days=entry.options.get(CONF_FORWARD_SCHEDULE_DAYS, DEFAULT_FORWARD_SCHEDULE_DAYS),
                    # F7: Announcement
                    announcement_enabled=entry.options.get(CONF_ANNOUNCEMENT_ENABLED, False),
                    announcement_file=entry.options.get(CONF_ANNOUNCEMENT_FILE, DEFAULT_ANNOUNCEMENT_FILE),
                    # F8: DTMF
                    dtmf_enabled=entry.options.get(CONF_DTMF_ENABLED, False),
                    dtmf_door_code=entry.options.get(CONF_DTMF_DOOR_CODE, DEFAULT_DTMF_DOOR_CODE),
                    dtmf_light_code=entry.options.get(CONF_DTMF_LIGHT_CODE, DEFAULT_DTMF_LIGHT_CODE),
                    # F12: Multi-button
                    doorbell_buttons=entry.options.get(CONF_DOORBELL_BUTTONS, {}),
                )
                
                # Give SIP manager access to Siedle API (for DTMF door opener)
                sip_manager.siedle_api = siedle
                
                # Create RTP Bridge
                rtp_bridge = RtpBridge()
                sip_manager.rtp_bridge = rtp_bridge
                
                # Set callbacks
                sip_manager.set_on_doorbell(
                    lambda data: _sip_doorbell_callback(hass, entry, data, sip_manager, rtp_bridge)
                )
                sip_manager.set_on_call_state_change(
                    lambda state, data: _sip_state_callback(hass, entry, state, data)
                )
                
                # Wire DTMF action callback (F8) — fires HA events when DTMF actions are executed
                if entry.options.get(CONF_DTMF_ENABLED, False):
                    def _dtmf_action_callback(action: str, code: str):
                        _LOGGER.info("DTMF action: %s (code=%s)", action, code)
                        hass.loop.call_soon_threadsafe(
                            hass.bus.async_fire,
                            f"{DOMAIN}_dtmf_action",
                            {
                                "action": action,
                                "code": code,
                                "entry_id": entry.entry_id,
                            },
                        )
                    sip_manager.set_on_dtmf_action(_dtmf_action_callback)
                
                # Start SIP manager in background
                _LOGGER.info("Starting new SIP Call Manager...")
                started = await hass.async_add_executor_job(sip_manager.start)
                
                if started:
                    hass.data[DOMAIN][entry.entry_id]["sip_manager"] = sip_manager
                    hass.data[DOMAIN][entry.entry_id]["rtp_bridge"] = rtp_bridge
                    _LOGGER.info("SIP Call Manager started successfully")
                    # Notify sensors immediately that SIP is now connected
                    async_dispatcher_send(hass, SIGNAL_SIEDLE_CONNECTION_UPDATE)
                else:
                    _LOGGER.warning("SIP Call Manager failed to start - falling back to legacy SIP listener")
                    sip_manager = None
                    # Fallback to old SIP listener
                    await hass.async_add_executor_job(
                        siedle.start_sip_listener,
                        lambda event_type, data: _sip_callback(hass, entry, event_type, data)
                    )
            else:
                _LOGGER.warning("No SIP credentials available - using legacy SIP listener")
                # Fallback to old SIP listener
                await hass.async_add_executor_job(
                    siedle.start_sip_listener,
                    lambda event_type, data: _sip_callback(hass, entry, event_type, data)
                )
                
        except Exception as e:
            _LOGGER.error(f"Failed to start SIP Call Manager: {e}")
            _LOGGER.exception(e)
            # Fallback to basic SIP listener
            try:
                await hass.async_add_executor_job(
                    siedle.start_sip_listener,
                    lambda event_type, data: _sip_callback(hass, entry, event_type, data)
                )
            except:
                pass

    # Setup platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Start MQTT if enabled (for device status)
    if entry.options.get("enable_mqtt", True):
        await hass.async_add_executor_job(
            siedle.connect_mqtt, 
            lambda topic, payload: _mqtt_callback(hass, entry, topic, payload)
        )
        # Notify sensors that MQTT connection state may have changed
        async_dispatcher_send(hass, SIGNAL_SIEDLE_CONNECTION_UPDATE)

    # ============== Setup FCM Push Handler (Primary Doorbell Detection) ==============
    # FCM is the most reliable way to detect doorbell rings!
    # Start in background to not block config entry setup
    if entry.options.get(CONF_FCM_ENABLED, True):  # Enabled by default!
        async def _start_fcm_handler():
            """Start FCM handler in background."""
            try:
                # Get access token for Siedle API
                access_token = siedle._token.get("access_token") if siedle._token else None
                
                if access_token:
                    # Get shared secret for name encryption
                    shared_secret = siedle._sharedSecret if hasattr(siedle, '_sharedSecret') else None
                    
                    # Get device name from options, or use HA location name
                    device_name = entry.options.get(
                        CONF_FCM_DEVICE_NAME,
                        hass.config.location_name or DEFAULT_FCM_DEVICE_NAME
                    )
                    
                    fcm_handler = SiedleFCMHandler(
                        hass=hass,
                        entry_id=entry.entry_id,
                        access_token=access_token,
                        shared_secret=shared_secret,
                        device_name=device_name,
                    )
                    
                    started = await fcm_handler.async_start()
                    if started:
                        hass.data[DOMAIN][entry.entry_id]["fcm_handler"] = fcm_handler
                        _LOGGER.info("✅ FCM doorbell detection started successfully!")
                        # Notify sensors immediately that FCM is now connected
                        async_dispatcher_send(hass, SIGNAL_SIEDLE_CONNECTION_UPDATE)
                    else:
                        _LOGGER.warning("Failed to start FCM handler - doorbell detection via FCM disabled")
                else:
                    _LOGGER.warning("No access token available for FCM registration")
            except Exception as e:
                _LOGGER.error(f"Failed to setup FCM handler: {e}")
                _LOGGER.exception(e)
        
        # Start FCM in background - don't block setup
        entry.async_create_background_task(hass, _start_fcm_handler(), "siedle_fcm_setup")

    # ============== Setup Fritz!Box Dialer (F13) ==============
    if entry.options.get(CONF_FRITZBOX_ENABLED, False):
        try:
            from .fritzbox import FritzBoxDialer
            
            fritzbox_dialer = FritzBoxDialer(
                host=entry.options.get(CONF_FRITZBOX_HOST, DEFAULT_FRITZBOX_HOST),
                username=entry.options.get(CONF_FRITZBOX_USER, DEFAULT_FRITZBOX_USER),
                password=entry.options.get(CONF_FRITZBOX_PASSWORD, ""),
                phone_number=entry.options.get(CONF_FRITZBOX_PHONE_NUMBER, ""),
            )
            hass.data[DOMAIN][entry.entry_id]["fritzbox_dialer"] = fritzbox_dialer
            _LOGGER.info("Fritz!Box dialer configured: %s", entry.options.get(CONF_FRITZBOX_HOST))
        except Exception as e:
            _LOGGER.error("Failed to setup Fritz!Box dialer: %s", e)

    # Register services
    await async_setup_services(hass, siedle)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        data = hass.data[DOMAIN][entry.entry_id]
        api = data["api"]
        sip_manager = data.get("sip_manager")
        rtp_bridge = data.get("rtp_bridge")
        
        # Stop SIP Call Manager
        if sip_manager:
            await hass.async_add_executor_job(sip_manager.stop)
        
        # Stop RTP Bridge
        if rtp_bridge:
            await hass.async_add_executor_job(rtp_bridge.stop)
        
        # Stop FCM Handler
        fcm_handler = data.get("fcm_handler")
        if fcm_handler:
            await fcm_handler.async_stop()
        
        # Close Fritz!Box session (F13)
        fritzbox_dialer = data.get("fritzbox_dialer")
        if fritzbox_dialer:
            await fritzbox_dialer.close()
        
        # Disconnect MQTT
        await hass.async_add_executor_job(api.disconnect_mqtt)
        
        # Stop legacy SIP listener (if used)
        await hass.async_add_executor_job(api.stop_sip_listener)
        
        # Stop legacy FCM listener (if used)
        await hass.async_add_executor_job(api.stop_fcm_listener)
        
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


def _mqtt_callback(hass: HomeAssistant, entry: ConfigEntry, topic: str, payload: dict):
    """Handle MQTT messages (called from MQTT thread)."""
    _LOGGER.debug("MQTT message: %s - %s", topic, payload)
    
    # Thread-safe: schedule on event loop
    hass.loop.call_soon_threadsafe(
        async_dispatcher_send, hass, SIGNAL_SIEDLE_CONNECTION_UPDATE
    )
    
    # Fire event for automations (thread-safe)
    hass.loop.call_soon_threadsafe(
        hass.bus.async_fire,
        f"{DOMAIN}_event",
        {
            "type": "mqtt",
            "topic": topic,
            "payload": payload,
            "entry_id": entry.entry_id,
        },
    )


def _sip_callback(hass: HomeAssistant, entry: ConfigEntry, event_type: str, data: dict):
    """Handle SIP doorbell events (called from SIP thread) - THIS IS THE MAIN DOORBELL DETECTION!"""
    _LOGGER.info("🔔 SIP DOORBELL event: type=%s, data=%s", event_type, data)
    
    # Fire event for automations (thread-safe)
    hass.loop.call_soon_threadsafe(
        hass.bus.async_fire,
        f"{DOMAIN}_event",
        {
            "type": "sip",
            "event_type": event_type,
            "from": data.get("from", ""),
            "call_id": data.get("call_id", ""),
            "entry_id": entry.entry_id,
        },
    )
    
    # Fire specific doorbell event (thread-safe)
    if event_type == "doorbell":
        hass.loop.call_soon_threadsafe(
            hass.bus.async_fire,
            f"{DOMAIN}_doorbell",
            {
                "source": "sip",
                "from": data.get("from", ""),
                "call_id": data.get("call_id", ""),
                "entry_id": entry.entry_id,
            },
        )


def _sip_doorbell_callback(hass: HomeAssistant, entry: ConfigEntry, data: dict, 
                           sip_manager, rtp_bridge):
    """
    Handle doorbell events from new SIP Call Manager.
    This callback is called when an INVITE is received from Siedle (doorbell ring).
    """
    _LOGGER.info("🔔🔔🔔 DOORBELL! From: %s", data.get("from", "unknown"))
    
    # Update call history sensor (F4)
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    call_history_sensor = entry_data.get("call_history_sensor")
    if call_history_sensor:
        call_history_sensor.start_call(data)
    
    # Trigger Fritz!Box dial (F13)
    fritzbox_dialer = entry_data.get("fritzbox_dialer")
    if fritzbox_dialer:
        asyncio.run_coroutine_threadsafe(
            fritzbox_dialer.dial_and_hangup(ring_duration=30), hass.loop
        )
    
    # Fire HA event (thread-safe)
    hass.loop.call_soon_threadsafe(
        hass.bus.async_fire,
        f"{DOMAIN}_doorbell",
        {
            "source": "sip",
            "from": data.get("from", ""),
            "call_id": data.get("call_id", ""),
            "caller_id": data.get("caller_id", ""),
            "caller_host": data.get("caller_host", ""),
            "button": data.get("button", "default"),
            "entry_id": entry.entry_id,
        },
    )
    
    # Recording is now handled automatically by SIP Manager when call is answered
    # (see _answer_siedle_call in sip_manager.py)


def _sip_state_callback(hass: HomeAssistant, entry: ConfigEntry, state, data: dict):
    """Handle SIP call state changes (called from SIP thread)."""
    _LOGGER.info("SIP call state changed: %s - %s", state.value if hasattr(state, 'value') else state, data)
    
    # Thread-safe: schedule on event loop
    hass.loop.call_soon_threadsafe(
        async_dispatcher_send, hass, SIGNAL_SIEDLE_CONNECTION_UPDATE
    )
    
    # Update call history sensor (F4)
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    call_history_sensor = entry_data.get("call_history_sensor")
    if call_history_sensor:
        state_val = state.value if hasattr(state, 'value') else str(state)
        if state_val == "answered":
            call_history_sensor.call_answered()
        elif state_val in ("idle", "ended"):
            call_history_sensor.call_ended(
                recording_file=data.get("recording_file"),
                dtmf_door_opened=data.get("dtmf_door_opened", False),
            )
    
    # Update recording sensor if recording file is available
    if "recording_file" in data:
        recording_file = data["recording_file"]
        recording_sensor = entry_data.get("last_recording_sensor")
        if recording_sensor:
            _LOGGER.info(f"Updating recording sensor with file: {recording_file}")
            recording_sensor.update_recording(recording_file)
    
    # Fire event for automations (thread-safe)
    hass.loop.call_soon_threadsafe(
        hass.bus.async_fire,
        f"{DOMAIN}_call_state",
        {
            "state": state.value if hasattr(state, 'value') else str(state),
            "data": data,
            "entry_id": entry.entry_id,
        },
    )


def _fcm_callback(hass: HomeAssistant, entry: ConfigEntry, event_type: str, data: dict):
    """Handle FCM push notifications (called from FCM thread)."""
    _LOGGER.info("FCM event: type=%s, data=%s", event_type, data)
    
    # Thread-safe: schedule on event loop
    hass.loop.call_soon_threadsafe(
        async_dispatcher_send, hass, SIGNAL_SIEDLE_CONNECTION_UPDATE
    )
    
    # Fire event for automations (thread-safe)
    hass.loop.call_soon_threadsafe(
        hass.bus.async_fire,
        f"{DOMAIN}_event",
        {
            "type": "fcm",
            "event_type": event_type,
            "title": data.get("title", ""),
            "body": data.get("body", ""),
            "entry_id": entry.entry_id,
        },
    )
    
    # Also fire a specific doorbell event for easier automation
    if event_type == "doorbell":
        hass.bus.fire(
            f"{DOMAIN}_doorbell",
            {
                "title": data.get("title", ""),
                "body": data.get("body", ""),
                "entry_id": entry.entry_id,
            },
        )


async def async_setup_services(hass: HomeAssistant, siedle: Siedle):
    """Setup Siedle services."""
    async def handle_open_door(call):
        """Handle open door service call."""
        contact_id = call.data.get(ATTR_CONTACT_ID)
        await hass.async_add_executor_job(siedle.openDoor, contact_id)

    async def handle_toggle_light(call):
        """Handle toggle light service call."""
        contact_id = call.data.get(ATTR_CONTACT_ID)
        await hass.async_add_executor_job(siedle.turnOnLight, contact_id)
    
    async def handle_activate_endpoint(call):
        """Handle activate endpoint service call."""
        _LOGGER.info("Endpoint activation requested - press the doorbell button now!")
        await hass.async_add_executor_job(siedle.activate_endpoint)

    async def handle_hangup(call):
        """Handle hangup call service."""
        # Find the SIP manager from any entry
        for entry_id, data in hass.data.get(DOMAIN, {}).items():
            if isinstance(data, dict) and "sip_manager" in data:
                sip_manager = data.get("sip_manager")
                if sip_manager and sip_manager.is_call_active:
                    await hass.async_add_executor_job(sip_manager.hangup)
                    _LOGGER.info("Call hung up via service")
                    return
        _LOGGER.warning("No active call to hang up")

    hass.services.async_register(DOMAIN, SERVICE_OPEN_DOOR, handle_open_door)
    hass.services.async_register(DOMAIN, SERVICE_TOGGLE_LIGHT, handle_toggle_light)
    hass.services.async_register(DOMAIN, "activate_endpoint", handle_activate_endpoint)
    hass.services.async_register(DOMAIN, SERVICE_HANGUP, handle_hangup)


class SiedleDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching Siedle data."""

    def __init__(self, hass: HomeAssistant, api: Siedle):
        """Initialize."""
        self.api = api
        self.hass = hass
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=5),
        )

    async def _async_update_data(self):
        """Update data via library."""
        try:
            # Get contacts and status
            contacts = await self.hass.async_add_executor_job(self.api.get_contacts)
            status = await self.hass.async_add_executor_job(self.api.getStatus)
            
            # Get SIP manager status if available
            sip_registered = False
            ext_sip_registered = False
            call_state = "idle"
            
            # Find entry for this API
            for entry_id, data in self.hass.data.get(DOMAIN, {}).items():
                if isinstance(data, dict) and data.get("api") == self.api:
                    sip_manager = data.get("sip_manager")
                    if sip_manager:
                        if hasattr(sip_manager, '_siedle_conn') and sip_manager._siedle_conn:
                            sip_registered = sip_manager._siedle_conn.registered
                        if hasattr(sip_manager, '_external_conn') and sip_manager._external_conn:
                            ext_sip_registered = sip_manager._external_conn.registered
                        if hasattr(sip_manager, 'state'):
                            call_state = sip_manager.state.value
                    break
            
            return {
                "contacts": contacts,
                "status": status,
                "mqtt_connected": self.api.mqtt_connected,
                "sip_registered": sip_registered or self.api.sip_registered,
                "ext_sip_registered": ext_sip_registered,
                "call_state": call_state,
            }
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")


QR_SCANNER_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Siedle QR-Code Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            padding: 20px;
        }
        .container {
            background: white; border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px; width: 100%; overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; text-align: center;
        }
        .header h1 { font-size: 24px; margin-bottom: 10px; }
        .header p { font-size: 14px; opacity: 0.9; }
        .content { padding: 30px; }
        #qr-reader {
            width: 100%; border-radius: 10px; overflow: hidden;
            background: #f0f0f0; position: relative;
        }
        #qr-reader video { width: 100%; height: auto; display: block; }
        .status {
            margin-top: 20px; padding: 15px; border-radius: 10px;
            text-align: center; font-size: 14px;
        }
        .status.info { background: #e3f2fd; color: #1976d2; }
        .status.success { background: #e8f5e9; color: #388e3c; }
        .status.error { background: #ffebee; color: #d32f2f; }
        .status.warning { background: #fff3e0; color: #f57c00; }
        .spinner {
            border: 3px solid #f3f3f3; border-top: 3px solid #667eea;
            border-radius: 50%; width: 40px; height: 40px;
            animation: spin 1s linear infinite; margin: 20px auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .overlay {
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            border: 3px solid #667eea; border-radius: 10px; pointer-events: none;
        }
        .scan-line {
            position: absolute; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, #667eea, transparent);
            animation: scan 2s linear infinite;
        }
        @keyframes scan { 0% { top: 0; } 100% { top: 100%; } }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 12px 30px;
            border-radius: 25px; font-size: 16px; cursor: pointer;
            margin-top: 15px; width: 100%; transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        button:active { transform: translateY(0); }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .manual-section { margin-top: 20px; display: none; }
        .manual-section .divider {
            text-align: center; margin: 20px 0; color: #999; font-size: 13px;
            display: flex; align-items: center; gap: 10px;
        }
        .manual-section .divider::before,
        .manual-section .divider::after {
            content: ''; flex: 1; height: 1px; background: #ddd;
        }
        .manual-section textarea {
            width: 100%; min-height: 120px; padding: 12px;
            border: 2px solid #ddd; border-radius: 10px;
            font-family: monospace; font-size: 12px;
            resize: vertical; transition: border-color 0.2s;
        }
        .manual-section textarea:focus { outline: none; border-color: #667eea; }
        .manual-section .hint { font-size: 12px; color: #888; margin-top: 8px; line-height: 1.5; }
        .http-warning {
            background: #fff3e0; border: 1px solid #ffcc02; border-radius: 10px;
            padding: 15px; margin-bottom: 15px; font-size: 13px; color: #e65100;
            display: none;
        }
        .http-warning b { color: #bf360c; }
        .tab-bar {
            display: flex; gap: 0; margin-bottom: 15px; border-radius: 10px;
            overflow: hidden; border: 2px solid #667eea;
        }
        .tab-bar button {
            flex: 1; margin: 0; border-radius: 0; padding: 10px; font-size: 14px;
            background: white; color: #667eea; transition: all 0.2s;
        }
        .tab-bar button:hover { transform: none; background: #f0f0ff; }
        .tab-bar button.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1F510; Siedle QR-Code Scanner</h1>
            <p>Scannen Sie Ihren Siedle QR-Code</p>
        </div>
        <div class="content">
            <div id="http-warning" class="http-warning">
                <b>&#x26A0;&#xFE0F; Kein HTTPS:</b> Die Kamera ben&ouml;tigt eine sichere Verbindung (HTTPS).
                Bitte verwenden Sie die manuelle Eingabe unten oder richten Sie HTTPS ein
                (z.B. &uuml;ber Nabu Casa oder einen Reverse Proxy).
            </div>
            <div class="tab-bar" id="tab-bar" style="display: none;">
                <button id="tab-scan" class="active" onclick="switchTab('scan')">
                    &#x1F4F7; Kamera Scan
                </button>
                <button id="tab-manual" onclick="switchTab('manual')">
                    &#x270D;&#xFE0F; Manuell
                </button>
            </div>
            <div id="scan-section">
                <div id="qr-reader"></div>
                <div id="status" class="status info">
                    <div class="spinner"></div>
                    Kamera wird initialisiert...
                </div>
                <button id="retry-btn" style="display: none;">Erneut versuchen</button>
            </div>
            <div id="manual-section" class="manual-section">
                <div class="divider">QR-Code Inhalt einf&uuml;gen</div>
                <textarea id="qr-input" placeholder="QR-Code Inhalt hier einf&uuml;gen... Scannen Sie den QR-Code mit einer beliebigen QR-App und f&uuml;gen Sie den Text hier ein. Der Inhalt beginnt typischerweise mit {&quot;susUrl&quot;:..."></textarea>
                <div class="hint">
                    &#x1F4A1; <b>So geht's:</b> &Ouml;ffnen Sie eine QR-Scanner App (z.B. die Kamera-App),
                    scannen Sie den Siedle QR-Code und kopieren Sie den erkannten Text.
                    F&uuml;gen Sie ihn dann hier ein.
                </div>
                <button id="submit-manual" onclick="submitManual()">&#x2705; QR-Daten absenden</button>
            </div>
        </div>
    </div>
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
    <script>
        var configFlowId = "%%CONFIG_FLOW_ID%%";
        var callbackUrl = "%%CALLBACK_URL%%";
        var statusDiv = document.getElementById('status');
        var retryBtn = document.getElementById('retry-btn');
        var manualSection = document.getElementById('manual-section');
        var scanSection = document.getElementById('scan-section');
        var tabBar = document.getElementById('tab-bar');
        var httpWarning = document.getElementById('http-warning');
        var html5QrCode = null;
        var isScanning = false;
        var isSecure = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';

        function switchTab(tab) {
            document.getElementById('tab-scan').className = tab === 'scan' ? 'active' : '';
            document.getElementById('tab-manual').className = tab === 'manual' ? 'active' : '';
            scanSection.style.display = tab === 'scan' ? 'block' : 'none';
            manualSection.style.display = tab === 'manual' ? 'block' : 'none';
        }

        function showManualFallback(showWarning) {
            tabBar.style.display = 'flex';
            if (showWarning) { httpWarning.style.display = 'block'; }
        }

        function showManualOnly() {
            tabBar.style.display = 'flex';
            httpWarning.style.display = 'block';
            switchTab('manual');
        }

        function submitManual() {
            var qrInput = document.getElementById('qr-input').value.trim();
            if (!qrInput) {
                document.getElementById('qr-input').style.borderColor = '#d32f2f';
                return;
            }
            if (!callbackUrl || !configFlowId) {
                manualSection.innerHTML = '<div class="status error">&#x274C; Fehlende Parameter</div>';
                return;
            }
            try { JSON.parse(qrInput); } catch(e) {
                document.getElementById('qr-input').style.borderColor = '#d32f2f';
                manualSection.querySelector('.hint').innerHTML = '<span style="color:#d32f2f">&#x274C; Der eingegebene Text ist kein g&uuml;ltiges JSON. Bitte pr&uuml;fen Sie den QR-Code Inhalt.</span>';
                return;
            }
            var encodedResult = encodeURIComponent(qrInput);
            var redirectUrl = callbackUrl + '?config_flow_id=' + configFlowId + '&result=' + encodedResult;
            document.getElementById('submit-manual').disabled = true;
            document.getElementById('submit-manual').textContent = 'Weiterleitung...';
            window.location.href = redirectUrl;
        }

        function updateStatus(message, type, showSpinner) {
            type = type || 'info';
            showSpinner = showSpinner || false;
            statusDiv.className = 'status ' + type;
            statusDiv.innerHTML = showSpinner
                ? '<div class="spinner"></div>' + message
                : message;
        }

        function onScanSuccess(decodedText) {
            if (isScanning) return;
            isScanning = true;
            updateStatus('&#x2705; QR-Code erfolgreich gescannt!', 'success');
            html5QrCode.stop().then(function() {
                if (callbackUrl && configFlowId) {
                    updateStatus('&#x1F504; Weiterleitung zu Home Assistant...', 'info', true);
                    var encodedResult = encodeURIComponent(decodedText);
                    var redirectUrl = callbackUrl + '?config_flow_id=' + configFlowId + '&result=' + encodedResult;
                    setTimeout(function() { window.location.href = redirectUrl; }, 1000);
                } else {
                    updateStatus('&#x274C; Fehlende Parameter: callback_url oder config_flow_id', 'error');
                    retryBtn.style.display = 'block';
                }
            }).catch(function(err) { console.error('Error stopping scanner:', err); });
        }

        function onScanError() { }

        function showCameraError(msg) {
            updateStatus(msg, 'error');
            retryBtn.style.display = 'block';
            showManualFallback(false);
        }

        function addOverlay() {
            var reader = document.getElementById('qr-reader');
            var overlay = document.createElement('div');
            overlay.className = 'overlay';
            var scanLine = document.createElement('div');
            scanLine.className = 'scan-line';
            overlay.appendChild(scanLine);
            reader.appendChild(overlay);
        }

        function startScanner() {
            if (!callbackUrl || !configFlowId) {
                updateStatus('&#x274C; Fehler: Fehlende URL-Parameter', 'error');
                retryBtn.style.display = 'block';
                return;
            }
            if (!isSecure) {
                updateStatus('&#x26A0;&#xFE0F; Kamera nicht verf&uuml;gbar (kein HTTPS). Bitte manuelle Eingabe verwenden.', 'warning');
                showManualOnly();
                return;
            }
            updateStatus('&#x1F4F7; Kameraberechtigung wird angefordert...', 'info', true);
            retryBtn.style.display = 'none';
            html5QrCode = new Html5Qrcode('qr-reader');
            var config = { fps: 10, qrbox: { width: 250, height: 250 }, aspectRatio: 1.0 };
            html5QrCode.start(
                { facingMode: 'environment' }, config, onScanSuccess, onScanError
            ).then(function() {
                updateStatus('&#x1F4F8; Bereit zum Scannen - Halten Sie den QR-Code vor die Kamera', 'info');
                showManualFallback(false);
                addOverlay();
            }).catch(function(err) {
                console.error('Camera error:', err);
                Html5Qrcode.getCameras().then(function(cameras) {
                    if (cameras && cameras.length > 0) {
                        updateStatus('&#x1F504; Starte Kamera...', 'warning', true);
                        html5QrCode.start(
                            cameras[0].id, config, onScanSuccess, onScanError
                        ).then(function() {
                            updateStatus('&#x1F4F8; Bereit zum Scannen - Halten Sie den QR-Code vor die Kamera', 'info');
                            showManualFallback(false);
                            addOverlay();
                        }).catch(function(err2) {
                            console.error('Fallback camera error:', err2);
                            showCameraError('&#x274C; Kamera konnte nicht gestartet werden.');
                        });
                    } else {
                        showCameraError('&#x274C; Keine Kamera gefunden.');
                    }
                }).catch(function(err2) {
                    console.error('Get cameras error:', err2);
                    showCameraError('&#x274C; Fehler beim Zugriff auf die Kamera: ' + err2);
                });
            });
        }

        retryBtn.addEventListener('click', function() {
            isScanning = false;
            if (html5QrCode) {
                html5QrCode.stop().then(function() { startScanner(); }).catch(function() { startScanner(); });
            } else { startScanner(); }
        });

        window.addEventListener('load', function() { setTimeout(startScanner, 500); });
    </script>
</body>
</html>"""


class SiedleQRScannerView(HomeAssistantView):
    """Serve the QR code scanner page directly from Home Assistant."""

    url = "/api/siedle/qr_scanner"
    name = "api:siedle:qr_scanner"
    requires_auth = False

    async def get(self, request):
        """Serve the QR scanner HTML page."""
        from aiohttp import web

        config_flow_id = request.query.get("config_flow_id", "")
        callback_url = request.query.get("callback_url", "")

        # If callback_url not provided as parameter, derive from request
        if not callback_url:
            scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
            host = request.headers.get("X-Forwarded-Host", request.host)
            callback_url = f"{scheme}://{host}/api/siedle/qr_callback"
            _LOGGER.debug("Derived callback_url from request: %s", callback_url)

        try:
            html_content = QR_SCANNER_HTML.replace(
                "%%CONFIG_FLOW_ID%%", config_flow_id
            ).replace(
                "%%CALLBACK_URL%%", callback_url
            )
            return web.Response(text=html_content, content_type="text/html")
        except Exception as err:
            _LOGGER.error("Error building QR scanner page: %s", err)
            return web.Response(text="Internal error", status=500)


class SiedleQRCallbackView(HomeAssistantView):
    """Handle QR code callback from external scanner."""

    url = "/api/siedle/qr_callback"
    name = "api:siedle:qr_callback"
    requires_auth = False

    async def get(self, request):
        """Handle GET request from QR scanner redirect."""
        from aiohttp import web
        
        # Get parameters
        config_flow_id = request.query.get("config_flow_id")
        result = request.query.get("result")

        if not config_flow_id or not result:
            return web.Response(
                text="Missing parameters. Please try again.",
                status=400
            )

        # Get the config flow manager
        hass = request.app["hass"]
        
        try:
            # Continue the flow with the QR data - external step erwartet user_input
            await hass.config_entries.flow.async_configure(
                flow_id=config_flow_id,
                user_input={"result": result}
            )
            
            # Redirect to Home Assistant config flow UI
            return web.Response(
                text="""
                <html>
                <head>
                    <title>Siedle QR Code Success</title>
                    <script>
                        // Versuche das Fenster zu schließen und zu Home Assistant zurückzukehren
                        setTimeout(function() {
                            window.close();
                            // Falls close nicht funktioniert, redirecte zu HA
                            if (!window.closed) {
                                window.location.href = '/';
                            }
                        }, 2000);
                    </script>
                </head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>✅ QR Code erfolgreich gescannt!</h1>
                    <p>Die Konfiguration wird fortgesetzt...</p>
                    <p>Dieses Fenster schließt sich automatisch.</p>
                </body>
                </html>
                """,
                content_type="text/html"
            )
                
        except Exception as err:
            _LOGGER.error("Error processing QR callback: %s", err)
            return web.Response(
                text=f"Error processing QR code: {err}",
                status=500
            )

