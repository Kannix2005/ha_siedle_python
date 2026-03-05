# Siedle Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/Kannix2005/ha_siedle_python.svg)](https://github.com/Kannix2005/ha_siedle_python/releases)
[![GitHub License](https://img.shields.io/github/license/Kannix2005/ha_siedle_python.svg)](LICENSE)

**[🇩🇪 Deutsche Version](README_DE.md)** | 🇬🇧 English Version

A complete Home Assistant integration for **Siedle IQ door stations (SUS2)** — fully reverse-engineered from the official Siedle app.

## Features

- 🚪 **Door Opener** — Open the door directly from Home Assistant
- 💡 **Door Light** — Control the light at the door station
- 🔔 **Doorbell Detection** — Instant detection via FCM push notifications and SIP INVITE
- 🎙️ **Audio Recording** — Automatic recording of door conversations as WAV file (SRTP → PCM)
- 📱 **SIP Forwarding** — Forward doorbell to external SIP phone (e.g., FritzBox, Asterisk, MicroSIP)
- 🔊 **Bidirectional Audio Bridge** — Two-way communication with the door via external SIP phone (SRTP ↔ RTP)
- ⏱️ **Call Timeout & Fallback** — Automatic timeout per forwarding target, then next target (F1)
- 📞 **Multiple Forwarding Targets** — Comma-separated numbers, tried sequentially (F2)
- 📊 **Call History** — Sensor with last X calls including timestamp, caller, duration (F4)
- 🕐 **Time-based Forwarding** — Forwarding only during specific hours/weekdays (F6)
- 🔈 **Please-Wait Announcement** — Play WAV file or tone during connection setup (F7)
- 🔢 **DTMF Door Opener** — Open door via phone keypress (e.g., #) during call (F8)
- 🎵 **Media Source** — Play recordings directly in HA Media Browser (F9)
- 🔍 **Diagnostics** — Complete system status for troubleshooting (F10)
- 🔘 **Multiple Doorbell Buttons** — Distinguish between different door station bell buttons (F12)
- 📡 **Fritz!Box Click-to-Dial** — Ring DECT phones via FritzBox using TR-064 (F13)
- 📷 **Camera Entity** — Stub for future door camera integration (F14)
- ❌ **Hangup Button** — End active calls directly from Home Assistant
- 📊 **Status Sensors** — SIP, MQTT, FCM connection status, call status, door contacts
- 🔒 **Secure Communication** — SIP over TLS, audio via SRTP (AES-CM-128-HMAC-SHA1-80)

---

## Prerequisites

- A **Siedle IQ System (SUS2)** with Siedle app set up
- Home Assistant (recommended: current version)
- **Network requirements for audio recording:**
  - Your Home Assistant must be reachable from the internet (port forwarding for RTP port, typically ~45000-65000)
  - Or: Your router must support 1:1 NAT / Full-Cone NAT (OPNSense, pfSense)
  - The integration uses STUN to automatically detect the external port

---

## Installation

### HACS (recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Kannix2005&repository=ha_siedle_python&category=integration)

Or manually in HACS:
1. Open HACS → Add "Custom repository"
2. URL: `https://github.com/Kannix2005/ha_siedle_python`, Category: Integration
3. Search for "Siedle" and install
4. Restart Home Assistant

### Manual

1. Copy the `custom_components/siedle` folder to `config/custom_components/siedle`
2. Restart Home Assistant

---

## Setup

### Step 1: Scan QR Code from Siedle App

> ⚠️ **Important:** You will likely need a **second device** (e.g., a tablet or a friend's phone) to scan the QR code from your phone screen. The QR code is displayed in the Siedle app and must be captured by the HA setup dialog.

1. Open the **Siedle app** on your smartphone
2. Go to **Settings** → **Add New Device**
3. A QR code is displayed — you'll need this in the next step

### Step 2: Set up Integration in Home Assistant

1. In HA, go to **Settings → Devices & Services → Add Integration**
2. Search for **"Siedle"**
3. You'll be redirected to a QR scanner page served directly by your Home Assistant instance:
   - **With camera** (HTTPS required): If your HA is accessible via HTTPS (e.g., Nabu Casa, Reverse Proxy), the phone camera can scan the QR code directly in the browser.
   - **Manual input**: If the camera doesn't work (e.g., HTTP-only setup, desktop browser, no camera permission), the scanner page offers a manual input field. Simply scan the QR code with any QR scanner app on your phone, copy the text content and paste it into the field.
4. Scan the QR code from the Siedle app (with the second device or webcam)
5. The data will be automatically transmitted to HA

### Step 3: Activate Endpoint

1. After the QR data is transferred, HA will prompt you: **"Now press the doorbell"**
2. Press the physical doorbell at the door station
3. The integration detects the push and activates the endpoint on the Siedle server

### Step 4: Configure Options

After successful setup, you can configure the following in the integration options:
- **Automatic Recording**: Records door conversations as WAV
- **FCM Push**: Doorbell detection (enabled by default)
- **External SIP Server**: Call forwarding to FritzBox, Asterisk & Co.
- **Call Forwarding**: Forward doorbell to external SIP phone with bidirectional audio

---

## Entities

### Binary Sensors
| Entity | Description |
|--------|-------------|
| `binary_sensor.siedle_doorbell` | Briefly turns "on" when doorbell is pressed (5 sec.) |
| `binary_sensor.siedle_mqtt_connection` | MQTT connection status to Siedle server |
| `binary_sensor.siedle_fcm_push_connection` | FCM push connection status |
| `binary_sensor.siedle_door_contact_*` | Availability of individual door contacts |

### Sensors
| Entity | Description |
|--------|-------------|
| `sensor.siedle_call_status` | Current status: Ready / Ringing / Connected / Recording |
| `sensor.siedle_sip_status` | SIP registration status (Siedle + external if configured) |
| `sensor.siedle_mqtt_status` | MQTT connection status as text |
| `sensor.siedle_last_recording` | Timestamp and path of last recording |

### Buttons
| Entity | Description |
|--------|-------------|
| `button.siedle_door_opener` | Open door |
| `button.siedle_door_light` | Turn on door light |
| `button.siedle_hangup` | End active call |

---

## Configuration Options

Via **Settings → Devices & Services → Siedle → Configure**:

### Recording

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Automatic recording on doorbell |
| Max. Duration | 30 sec. | Maximum recording duration |
| Storage Path | `www/siedle_recordings` | Directory for WAV files |

> ⚠️ **Note:** Recording conversations at the door may be legally problematic. Please ensure you comply with local privacy laws (e.g., GDPR, data protection laws).

When recording is enabled, the call is automatically answered (Auto-Answer), audio data is received via SRTP, decrypted, and saved as a WAV file. After the recording duration expires, the call is automatically ended (Auto-Hangup).

### FCM Push Notifications

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | On | FCM-based doorbell detection |
| Device Name | HA Location Name | Name displayed in Siedle app |

FCM is the **primary and most reliable method** for doorbell detection. The integration emulates an Android device and receives Firebase Cloud Messages directly.

> ⚠️ **Note on Push Limits:** The Siedle servers send only **one single push notification** when the doorbell is pressed multiple times within **10 minutes**. This is a limitation of the Siedle system, not the integration. The integration detects all doorbell events via SIP INVITE — only the FCM push notification is throttled.

### External SIP Server

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Enable external SIP server for call forwarding |
| Host | — | IP or hostname (e.g., `192.168.178.1` for FritzBox) |
| Port | 5060 | SIP port |
| Username | — | SIP username for REGISTER |
| Password | — | SIP password |
| Transport | UDP | UDP, TCP, or TLS |

### Call Forwarding

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Forwarding on doorbell |
| Target Number | — | e.g., `**9` (FritzBox broadcast) |
| Caller ID | — | CallerID for external phone |
| Auto-Answer | Off | Automatically answer door station |

---

## Events

The integration fires the following HA events that can be used in automations:

```yaml
# On every Siedle event (FCM, MQTT, SIP)
event_type: siedle_event
data:
  type: "fcm" | "mqtt" | "sip"
  event_type: "doorbell"
  entry_id: "..."

# Specifically on doorbell
event_type: siedle_doorbell
data:
  source: "sip" | "fcm"
  entry_id: "..."

# On call state changes
event_type: siedle_call_state
data:
  state: "idle" | "ringing" | "connected" | "recording"
  data: { ... }
  entry_id: "..."
```

### Automation Example

```yaml
automation:
  - alias: "Doorbell Notification"
    trigger:
      - platform: state
        entity_id: binary_sensor.siedle_doorbell
        to: "on"
    action:
      - action: notify.mobile_app
        data:
          message: "Someone is at the door!"
          data:
            push:
              sound: "default"
              interruption-level: "time-sensitive"
```

---

## Services

| Service | Description |
|---------|-------------|
| `siedle.open_door` | Opens the door (optional: `contact_id`) |
| `siedle.toggle_light` | Toggles door light (optional: `contact_id`) |
| `siedle.hangup_call` | Ends active call |
| `siedle.activate_endpoint` | Activate endpoint — press doorbell! |

---

## Technical Architecture

This integration communicates with the Siedle SUS2 cloud system via multiple protocols:

### Communication Channels

```
┌─────────────┐        REST API (HTTPS)        ┌──────────────────┐
│             │◄──────────────────────────────►│                  │
│  Home       │      SIP/TLS (:5061)           │  Siedle Cloud    │
│  Assistant  │◄──────────────────────────────►│  (sus2.siedle.   │
│             │      SRTP (UDP, dynamic)       │   com)           │
│             │◄──────────────────────────────►│                  │
│             │      MQTT (SSL)                │                  │
│             │◄──────────────────────────────►│                  │
│             │      FCM (Push)                │                  │
│             │◄───────────────────────────────│                  │
└─────────────┘                                └──────────────────┘
```

| Protocol | Purpose | Details |
|----------|---------|---------|
| **REST API** | Authentication, contacts, door opener, light | OAuth2 via `sus2.siedle.com` |
| **SIP/TLS** | Call signaling | Port 5061, client certificate not required |
| **SRTP** | Audio transmission (encrypted) | AES_CM_128_HMAC_SHA1_80, PCMA/8000, RFC 4568 (SDES) |
| **MQTT** | Device status, events | TLS, notifications about status changes |
| **FCM** | Push doorbell detection | Firebase Cloud Messaging, emulated Android device |

### SIP & Audio in Detail

The SIP connection is the heart of the call and recording functionality:

1. **Registration:** The integration registers via SIP REGISTER to `sus2-sip.siedle.com:5061` (TLS)
2. **Incoming Call:** On doorbell, Siedle sends a SIP INVITE
3. **Answer:** The integration responds with `100 Trying`, then `200 OK` with SDP
4. **Audio:** SRTP-encrypted audio data (PCMA/G.711a, 8kHz) is received
5. **Recording:** SRTP packets are decrypted and saved as WAV file
6. **End:** After recording duration expires, a SIP BYE is automatically sent

#### NAT Traversal

Since Home Assistant typically runs behind a NAT router, the integration implements:

- **STUN** (RFC 5389): Determines public IP and external port from actual RTP socket
- **Via `received=` Parsing**: Detects public IP seen by Siedle from SIP header
- **NAT Punch-Through**: Sends empty PCMA packets to open NAT mapping
- **RTP Keepalive**: Continuous silence packets (every 20ms) keep NAT mapping open
- **Multi-Via Header**: All Via headers are correctly copied in SIP responses (RFC 3261)
- **Record-Route**: All Record-Route headers from INVITE are adopted

#### SRTP Encryption

- **Algorithm:** AES_CM_128_HMAC_SHA1_80 (RFC 3711)
- **Key Exchange:** SDES via SDP (RFC 4568) — each side generates its own master key
- **Key Derivation:** SRTP Key Derivation Function with label-based session keys
- **Authentication:** HMAC-SHA1, 80-bit tag on each packet

---

## Debugging

### Enable Logs

```yaml
logger:
  default: info
  logs:
    custom_components.siedle: debug
    custom_components.siedle.sip_manager: debug
    custom_components.siedle.rtp_handler: debug
    custom_components.siedle.srtp_handler: debug
    custom_components.siedle.fcm_handler: debug
```

### Common Issues

| Problem | Solution |
|---------|----------|
| No audio in recording | Check NAT configuration — router must allow UDP packets. Check logs for STUN results. |
| FCM not connecting | FCM needs ~10-30 sec. to start. Token refresh happens automatically. |
| SIP not registering | Check TLS connection to `sus2-sip.siedle.com:5061`. Check firewall rules. |
| Door opener not working | `sharedSecret` must be correctly decrypted — look for "Restored decrypted sharedSecret" in log. |
| Recording stops immediately | Check if RTP port is externally accessible. STUN log shows expected port. |

### Useful Log Messages

```
# Successful SIP registration:
"Siedle SIP registered successfully"

# SRTP keys generated:
"Generated local SRTP crypto line"

# Audio packets received:
"Received N audio bytes from Siedle, decrypted M samples"

# NAT detection:
"STUN discovered external address: x.x.x.x:yyyyy"
"Public IP from SIP Via received=: x.x.x.x"
```

---

## Known Limitations

- **No video support:** Siedle SUS2 does not transmit video via SIP — the camera image is only shown in the official app.
- **Only one active call:** The integration supports only one simultaneous call.
- **Cloud dependency:** All communication goes through Siedle cloud servers — no local fallback possible.

---

## Support

- 🐛 **Report bug**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)
- 💡 **Request feature**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)

## License

GPL-3.0 License — see [LICENSE](LICENSE)
