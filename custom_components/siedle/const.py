"""Constants for Siedle integration."""
DOMAIN = "siedle"

# Config Flow
CONF_QR_CODE_URL = "http://www.stefan-altheimer.de/siedle/index.html"

# Defaults
DEFAULT_NAME = "Siedle"
DEFAULT_SCAN_INTERVAL = 300

# Services
SERVICE_OPEN_DOOR = "open_door"
SERVICE_TOGGLE_LIGHT = "toggle_light"
SERVICE_HANGUP = "hangup_call"
SERVICE_CALL_DOOR = "call_door"

# Attributes
ATTR_CONTACT_ID = "contact_id"
ATTR_CONTACT_NAME = "contact_name"

# Device Classes
DEVICE_CLASS_DOOR = "door"

# ==================== External SIP Configuration ====================
CONF_EXT_SIP_ENABLED = "ext_sip_enabled"
CONF_EXT_SIP_HOST = "ext_sip_host"
CONF_EXT_SIP_PORT = "ext_sip_port"
CONF_EXT_SIP_USERNAME = "ext_sip_username"
CONF_EXT_SIP_PASSWORD = "ext_sip_password"
CONF_EXT_SIP_TRANSPORT = "ext_sip_transport"  # udp, tcp, tls

# Default external SIP settings
DEFAULT_EXT_SIP_PORT = 5060
DEFAULT_EXT_SIP_TRANSPORT = "udp"

# ==================== Call Forwarding Configuration ====================
CONF_FORWARD_ENABLED = "forward_enabled"
CONF_FORWARD_TO_NUMBER = "forward_to_number"  # Nummer am ext SIP bei Klingel anrufen
CONF_FORWARD_FROM_NUMBER = "forward_from_number"  # Nummer die zur Tür forwarden darf
CONF_AUTO_ANSWER = "auto_answer"  # Automatisch Tür-Call annehmen

# ==================== Recording Configuration ====================
CONF_RECORDING_ENABLED = "recording_enabled"
CONF_RECORDING_DURATION = "recording_duration"  # Sekunden
CONF_RECORDING_PATH = "recording_path"

# Default recording settings
DEFAULT_RECORDING_DURATION = 30  # 30 Sekunden
DEFAULT_RECORDING_PATH = "www/siedle_recordings"

# ==================== FCM Configuration ====================
CONF_FCM_ENABLED = "fcm_enabled"  # FCM-based doorbell detection (recommended!)
CONF_FCM_DEVICE_NAME = "fcm_device_name"  # Device name shown in Siedle main app
DEFAULT_FCM_DEVICE_NAME = "Home Assistant"

# ==================== Call States ====================
CALL_STATE_IDLE = "idle"
CALL_STATE_RINGING = "ringing"
CALL_STATE_CONNECTED = "connected"
CALL_STATE_RECORDING = "recording"

# ==================== SIP Constants ====================
SIP_TRANSPORT_UDP = "udp"
SIP_TRANSPORT_TCP = "tcp"
SIP_TRANSPORT_TLS = "tls"

SIP_TRANSPORTS = [SIP_TRANSPORT_UDP, SIP_TRANSPORT_TCP, SIP_TRANSPORT_TLS]

# ==================== Dispatcher Signals ====================
SIGNAL_SIEDLE_CONNECTION_UPDATE = f"{DOMAIN}_connection_update"
