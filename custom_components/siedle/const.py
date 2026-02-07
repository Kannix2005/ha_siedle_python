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
CONF_FORWARD_TO_NUMBER = "forward_to_number"  # Kommasepariert für mehrere Ziele
CONF_FORWARD_FROM_NUMBER = "forward_from_number"  # Nummer die zur Tür forwarden darf
CONF_AUTO_ANSWER = "auto_answer"  # Automatisch Tür-Call annehmen

# Call Timeout (F1)
CONF_FORWARD_TIMEOUT = "forward_timeout"  # Sekunden bis Timeout bei Weiterleitung
DEFAULT_FORWARD_TIMEOUT = 30  # 30 Sekunden

# ==================== Time-Based Forwarding (F6) ====================
CONF_FORWARD_SCHEDULE_ENABLED = "forward_schedule_enabled"
CONF_FORWARD_SCHEDULE_START = "forward_schedule_start"  # "HH:MM"
CONF_FORWARD_SCHEDULE_END = "forward_schedule_end"  # "HH:MM"
CONF_FORWARD_SCHEDULE_DAYS = "forward_schedule_days"  # [0-6] Mo-So

DEFAULT_FORWARD_SCHEDULE_START = "00:00"
DEFAULT_FORWARD_SCHEDULE_END = "23:59"
DEFAULT_FORWARD_SCHEDULE_DAYS = [0, 1, 2, 3, 4, 5, 6]  # Alle Tage

# ==================== DTMF Door Opener (F8) ====================
CONF_DTMF_ENABLED = "dtmf_enabled"
CONF_DTMF_DOOR_CODE = "dtmf_door_code"  # z.B. "#" oder "1234#"
CONF_DTMF_LIGHT_CODE = "dtmf_light_code"  # z.B. "*" für Türlicht

DEFAULT_DTMF_DOOR_CODE = "#"
DEFAULT_DTMF_LIGHT_CODE = "*"

# ==================== Announcement / Bitte-warten (F7) ====================
CONF_ANNOUNCEMENT_ENABLED = "announcement_enabled"
CONF_ANNOUNCEMENT_FILE = "announcement_file"  # Pfad zu WAV-Datei

DEFAULT_ANNOUNCEMENT_FILE = ""  # Leer = integrierter Signalton

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

# ==================== FritzBox Click-to-Dial (F13) ====================
CONF_FRITZBOX_ENABLED = "fritzbox_enabled"
CONF_FRITZBOX_HOST = "fritzbox_host"
CONF_FRITZBOX_USER = "fritzbox_user"
CONF_FRITZBOX_PASSWORD = "fritzbox_password"
CONF_FRITZBOX_PHONE_NUMBER = "fritzbox_phone_number"  # Interne Nummer die angerufen wird

DEFAULT_FRITZBOX_HOST = "fritz.box"
DEFAULT_FRITZBOX_USER = "admin"

# ==================== Doorbell Buttons / Multi-Button (F12) ====================
CONF_DOORBELL_BUTTONS = "doorbell_buttons"  # JSON list [{name, pattern}]

# ==================== Call History (F4) ====================
CONF_CALL_HISTORY_SIZE = "call_history_size"
DEFAULT_CALL_HISTORY_SIZE = 50

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

# ==================== DTMF Event Codes (RFC 4733) ====================
DTMF_EVENT_MAP = {
    0: "0", 1: "1", 2: "2", 3: "3", 4: "4",
    5: "5", 6: "6", 7: "7", 8: "8", 9: "9",
    10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D",
}
