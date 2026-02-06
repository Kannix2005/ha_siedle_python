"""Config flow for Siedle integration."""
import logging
import voluptuous as vol
import json
from urllib.parse import quote

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    DOMAIN,
    CONF_QR_CODE_URL,
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
    SIP_TRANSPORTS,
    CONF_FCM_ENABLED,
    CONF_FCM_DEVICE_NAME,
    DEFAULT_FCM_DEVICE_NAME,
)

_LOGGER = logging.getLogger(__name__)


class SiedleFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Siedle."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_PUSH

    def __init__(self):
        """Initialize the config flow."""
        self._setup_data = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step - redirect to external QR scanner."""
        # Stelle sicher, dass die QR Callback View registriert ist
        from . import SiedleQRCallbackView
        try:
            view_registered = any(
                hasattr(view, 'name') and view.name == "api:siedle:qr_callback" 
                for view in self.hass.http.app.router._resources
            )
            if not view_registered:
                _LOGGER.info("Registering Siedle QR callback view at /api/siedle/qr_callback")
                self.hass.http.register_view(SiedleQRCallbackView())
            else:
                _LOGGER.debug("Siedle QR callback view already registered")
        except Exception as e:
            _LOGGER.error("Error registering view: %s", e)
        
        # Build callback URL for QR scanner
        base_url = self.hass.config.external_url or self.hass.config.internal_url
        if not base_url:
            base_url = "http://homeassistant.local:8123"

        flow_id = self.flow_id
        callback_url = quote(f"{base_url}/api/siedle/qr_callback", safe=':/')
        qr_scanner_url = f"{CONF_QR_CODE_URL}?config_flow_id={flow_id}&callback_url={callback_url}"

        return self.async_external_step(
            step_id="qr_scan",
            url=qr_scanner_url,
        )

    async def async_step_qr_scan(self, user_input=None):
        """Handle the QR scan step - waiting for external callback."""
        _LOGGER.debug(f"async_step_qr_scan called with user_input: {user_input}")
        
        if user_input is None:
            # Still waiting for callback
            return self.async_external_step_done(next_step_id="qr_scan")

        # Callback received - mark external step as done and move to processing
        _LOGGER.info("QR data received via callback")
        self._setup_data = user_input.get("result")
        
        # External step must be marked as done before transitioning to regular step
        return self.async_external_step_done(next_step_id="process_qr")

    async def async_step_process_qr(self, user_input=None):
        """Process the QR code data after external step is done."""
        _LOGGER.debug("Processing QR code data...")
        
        try:
            qr_data = self._setup_data
            
            if not qr_data:
                _LOGGER.error("No QR data available")
                return self.async_abort(reason="invalid_qr")

            setup_info = json.loads(qr_data)
            _LOGGER.debug(f"Parsed setup_info: {setup_info.keys()}")

            # Validate required fields
            if "susUrl" not in setup_info or (
                "setupKey" not in setup_info and "endpointSetupKey" not in setup_info
            ):
                _LOGGER.error("Missing required fields in setup_info")
                return self.async_abort(reason="invalid_qr")

            # Try to authorize
            from .siedle_api import Siedle

            try:
                _LOGGER.info("Creating Siedle instance...")
                siedle = await self.hass.async_add_executor_job(
                    lambda: Siedle(setupInfo=setup_info)
                )
                
                # Check if siedle._endpoint_id exists
                if not hasattr(siedle, '_endpoint_id') or not siedle._endpoint_id:
                    _LOGGER.error("Siedle authorization failed - no endpoint_id received")
                    return self.async_abort(reason="cannot_connect")
                
                _LOGGER.info(f"Successfully created entry for endpoint {siedle._endpoint_id}")
                return self.async_create_entry(
                    title=f"Siedle {siedle._endpoint_id[:8]}",
                    data={
                        "setup_info": setup_info,
                        "endpoint_id": siedle._endpoint_id,
                        "token": siedle._token,  # Save token for reuse
                        "setup_data": siedle._setupData,  # Save encrypted setupData
                        "shared_secret": siedle._sharedSecret.hex() if siedle._sharedSecret else None,  # Save DECRYPTED secret!
                        "transfer_secret": siedle._transferSecret if hasattr(siedle, '_transferSecret') else None,  # Save for endpoint activation
                    },
                )
            except KeyError as err:
                _LOGGER.error("Siedle API response missing field: %s", err)
                _LOGGER.error("This might indicate an API error or invalid setup key")
                return self.async_abort(reason="cannot_connect")
            except Exception as err:
                _LOGGER.exception("Failed to authorize with Siedle: %s", err)
                return self.async_abort(reason="cannot_connect")

        except json.JSONDecodeError:
            _LOGGER.error("Invalid JSON in QR code data")
            return self.async_abort(reason="invalid_qr")
        except Exception as err:
            _LOGGER.exception("Unexpected error: %s", err)
            return self.async_abort(reason="unknown")

    async def async_step_import(self, import_data):
        """Handle import from configuration.yaml."""
        return await self.async_step_user(import_data)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return SiedleOptionsFlowHandler()


class SiedleOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Siedle options."""

    async def async_step_init(self, user_input=None):
        """Manage the options - main menu."""
        return self.async_show_menu(
            step_id="init",
            menu_options={
                "general": "Allgemeine Einstellungen",
                "external_sip": "Externer SIP Server",
                "call_forwarding": "Anrufweiterleitung",
                "recording": "Aufzeichnung",
            },
        )

    async def async_step_general(self, user_input=None):
        """General settings (MQTT, FCM, SIP)."""
        if user_input is not None:
            # Merge with existing options
            new_options = {**self.config_entry.options, **user_input}
            return self.async_create_entry(title="", data=new_options)

        return self.async_show_form(
            step_id="general",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_FCM_ENABLED,
                        default=self.config_entry.options.get(CONF_FCM_ENABLED, True),
                    ): bool,
                    vol.Optional(
                        CONF_FCM_DEVICE_NAME,
                        default=self.config_entry.options.get(CONF_FCM_DEVICE_NAME, DEFAULT_FCM_DEVICE_NAME),
                    ): str,
                    vol.Optional(
                        "enable_mqtt",
                        default=self.config_entry.options.get("enable_mqtt", True),
                    ): bool,
                    vol.Optional(
                        "enable_sip",
                        default=self.config_entry.options.get("enable_sip", True),
                    ): bool,
                }
            ),
            description_placeholders={
                "fcm_description": "FCM ist die zuverlässigste Methode für Klingelerkennung (empfohlen!)",
            },
        )

    async def async_step_external_sip(self, user_input=None):
        """External SIP server settings."""
        if user_input is not None:
            new_options = {**self.config_entry.options, **user_input}
            return self.async_create_entry(title="", data=new_options)

        return self.async_show_form(
            step_id="external_sip",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_EXT_SIP_ENABLED,
                        default=self.config_entry.options.get(CONF_EXT_SIP_ENABLED, False),
                    ): bool,
                    vol.Optional(
                        CONF_EXT_SIP_HOST,
                        default=self.config_entry.options.get(CONF_EXT_SIP_HOST, ""),
                    ): str,
                    vol.Optional(
                        CONF_EXT_SIP_PORT,
                        default=self.config_entry.options.get(CONF_EXT_SIP_PORT, DEFAULT_EXT_SIP_PORT),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                    vol.Optional(
                        CONF_EXT_SIP_USERNAME,
                        default=self.config_entry.options.get(CONF_EXT_SIP_USERNAME, ""),
                    ): str,
                    vol.Optional(
                        CONF_EXT_SIP_PASSWORD,
                        default=self.config_entry.options.get(CONF_EXT_SIP_PASSWORD, ""),
                    ): str,
                    vol.Optional(
                        CONF_EXT_SIP_TRANSPORT,
                        default=self.config_entry.options.get(CONF_EXT_SIP_TRANSPORT, DEFAULT_EXT_SIP_TRANSPORT),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=SIP_TRANSPORTS,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
            description_placeholders={
                "example_host": "z.B. fritz.box, asterisk.local, sipgate.de",
            },
        )

    async def async_step_call_forwarding(self, user_input=None):
        """Call forwarding settings."""
        if user_input is not None:
            new_options = {**self.config_entry.options, **user_input}
            return self.async_create_entry(title="", data=new_options)

        return self.async_show_form(
            step_id="call_forwarding",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_FORWARD_ENABLED,
                        default=self.config_entry.options.get(CONF_FORWARD_ENABLED, False),
                    ): bool,
                    vol.Optional(
                        CONF_FORWARD_TO_NUMBER,
                        default=self.config_entry.options.get(CONF_FORWARD_TO_NUMBER, ""),
                    ): str,
                    vol.Optional(
                        CONF_FORWARD_FROM_NUMBER,
                        default=self.config_entry.options.get(CONF_FORWARD_FROM_NUMBER, ""),
                    ): str,
                    vol.Optional(
                        CONF_AUTO_ANSWER,
                        default=self.config_entry.options.get(CONF_AUTO_ANSWER, False),
                    ): bool,
                }
            ),
            description_placeholders={
                "forward_to_help": "Nummer die bei Klingeln angerufen wird (z.B. **620 für FritzBox Telefon)",
                "forward_from_help": "Nummer von der Anrufe zur Tür weitergeleitet werden",
            },
        )

    async def async_step_recording(self, user_input=None):
        """Recording settings."""
        if user_input is not None:
            new_options = {**self.config_entry.options, **user_input}
            return self.async_create_entry(title="", data=new_options)

        return self.async_show_form(
            step_id="recording",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_RECORDING_ENABLED,
                        default=self.config_entry.options.get(CONF_RECORDING_ENABLED, False),
                    ): bool,
                    vol.Optional(
                        CONF_RECORDING_DURATION,
                        default=self.config_entry.options.get(CONF_RECORDING_DURATION, DEFAULT_RECORDING_DURATION),
                    ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
                    vol.Optional(
                        CONF_RECORDING_PATH,
                        default=self.config_entry.options.get(CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH),
                    ): str,
                }
            ),
            description_placeholders={
                "path_help": "Relativer Pfad im HA config Ordner (z.B. www/siedle_recordings)",
            },
        )
