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
- **Recording**: Records door conversations as WAV, call history size
- **General**: FCM push, device name, MQTT and SIP on/off
- **External SIP Server**: Call forwarding to FRITZ!Box, Asterisk & Co.
- **Call Forwarding**: Forward doorbell to external SIP phone with bidirectional audio (targets, timeout, auto-answer)
- **Forwarding Schedule**: Forward only at certain times/weekdays
- **DTMF Door Opener**: Open the door / switch the light by keypress during a call
- **Wait Announcement** and **FRITZ!Box Integration**

---

## Entities

All entities belong to one device named `Siedle <first 8 characters of the endpoint ID>` (except the camera, which has no device). The entity names are fixed German names set in the code (not translated). Home Assistant builds the entity ID from the device name and the entity name, so the exact IDs depend on your installation — look them up under **Settings → Devices & Services → Siedle → Devices**. The tables below therefore list entity names, not IDs.

### Binary Sensors
| Entity name | Description |
|-------------|-------------|
| Türklingel | Briefly turns "on" (5 sec.) when the doorbell is pressed (reacts to the `siedle_doorbell` event, FCM doorbell events and MQTT topics that look like a doorbell) |
| MQTT Verbindung | MQTT connection status to Siedle server |
| FCM Push Verbindung | FCM push connection status |
| Türkontakt `<call number>` | One per door contact: "on" if the contact has a door opener. Attributes: `contact_id`, `call_number`, `callable`, `has_camera`, `has_door_opener`, `has_door_light` |

### Sensors
| Entity name | Description |
|-------------|-------------|
| Anrufstatus | Current call status: `Bereit` (idle) / `Verbunden` (connected) / `Aufnahme` (recording); other internal states (`ringing_in`, `ringing_out`, `ending`) are shown as raw text. Only with SIP enabled. Attributes: `call_active` plus data of the last state change |
| SIP Status | `Beide verbunden` / `Siedle verbunden` / `Extern verbunden` / `Getrennt`. Attributes: `siedle_sip_registered`, `external_sip_registered` |
| MQTT Status | `Verbunden` / `Getrennt`. Attribute: `mqtt_connected` |
| Letzte Aufnahme | Timestamp of the last recording. Attributes: `filepath`, `filesize`, `media_url` (only for paths below `www/`) |
| Anruf-Historie | Number of stored calls. Attributes: `total_calls`, `calls_today`, `last_calls` (last 10, newest first: `timestamp`, `from`, `caller_id`, `call_id`, `source`, `answered`, `duration_seconds`, `recording_file`, `dtmf_door_opened`), `active_call` |

### Buttons
| Entity name | Description |
|-------------|-------------|
| Tür öffnen | Open door |
| Licht | Turn on door light |
| Auflegen | End active call (only with SIP enabled) |

### Camera
| Entity name | Description |
|-------------|-------------|
| Türstation Kamera | Placeholder only: no video stream and, at the moment, no image is ever delivered |

---

## Configuration Options

Via **Settings → Devices & Services → Siedle → Configure**:

### Recording

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Automatic recording on doorbell |
| Max. Duration | 30 sec. | Maximum recording duration (5–300 sec.) |
| Storage Path | `www/siedle_recordings` | Directory for WAV files (relative to the HA config folder) |
| Call History Size | 50 | Number of calls kept by the *Anruf-Historie* sensor (10–500) |

> ⚠️ **Note:** Recording conversations at the door may be legally problematic. Please ensure you comply with local privacy laws (e.g., GDPR, data protection laws).

When recording is enabled, the call is automatically answered (Auto-Answer), audio data is received via SRTP, decrypted, and saved as a WAV file. After the recording duration expires, the call is automatically ended (Auto-Hangup).

### General / FCM Push Notifications

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | On | FCM-based doorbell detection |
| Device Name | HA Location Name | Name displayed in Siedle app |
| MQTT | On | MQTT connection for device status |
| SIP | On | SIP registration for doorbell detection and call handling (without it there are no call status/hangup entities and no forwarding) |

FCM is the **primary and most reliable method** for doorbell detection. The integration emulates an Android device and receives Firebase Cloud Messages directly.

> ⚠️ **Note on Push Limits:** The Siedle servers send only **one single push notification** when the doorbell is pressed multiple times within **10 minutes**. This is a limitation of the Siedle system, not the integration. The integration detects all doorbell events via SIP INVITE — only the FCM push notification is throttled.

### External SIP Server

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Enable external SIP server for call forwarding |
| Host | — | IP or hostname (e.g., `192.168.178.1` for FritzBox) |
| Port | 5060 | SIP port (1–65535) |
| Username | — | SIP username for REGISTER |
| Password | — | SIP password |
| Transport | UDP | UDP, TCP, or TLS |

Servers that require a digest login for the forwarded call (`401`/`407`, e.g. a FRITZ!Box set up as IP door intercom) are supported since 3.1.5.

### Call Forwarding

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Forwarding on doorbell |
| Target Number | — | e.g., `**9` (FritzBox broadcast); several targets comma-separated (e.g. `**620,**621`), tried one after another |
| Allowed Caller Number | — | Filter for calls **from** the external SIP server **to** the door: an incoming call is only accepted if this number is contained in its From header, otherwise it is rejected with `403`. Empty = accept every caller. Nothing is sent as a caller ID. |
| Timeout | 30 sec. | Ring time per target before the next one is tried (5–120 sec.) |
| Auto-Answer | Off | Automatically answer door station |

### Forwarding Schedule

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Forward only within the schedule (otherwise always, when forwarding is enabled) |
| Start / End | `00:00` / `23:59` | Time range `HH:MM`; a range across midnight (e.g. `22:00`–`06:00`) is supported |
| Active Days | Mon–Sun | Weekdays on which forwarding is active |

### DTMF Door Opener

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Evaluate key presses during a forwarded call |
| Door Code | `#` | Code that opens the door (single key or sequence, e.g. `1234#`) |
| Light Code | `*` | Code that switches the door light (e.g. `*` or `56*`) |

Key presses are recognized both as RFC 4733 telephone events in the RTP stream and as SIP INFO (`application/dtmf-relay`, `application/dtmf`), which the FRITZ!Box uses. A key reported on both paths counts once. Multi-key codes are evaluated after a 3-second pause in typing; the entered sequence must end with the code. Every executed action fires the `siedle_dtmf_action` event.

### Wait Announcement

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Play a "please wait" announcement |
| WAV File | empty | Path to a WAV file (8 kHz, 16-bit, mono); empty = built-in beep |

> ℹ️ The option is saved, but the current code does not play the announcement yet (nothing calls the playback function).

### FRITZ!Box Integration

| Option | Default | Description |
|--------|---------|-------------|
| Enabled | Off | Ring a FRITZ!Box phone via TR-064 on doorbell (rings for 30 sec., then hangs up) |
| Host | `fritz.box` | FRITZ!Box address |
| Username | `admin` | FRITZ!Box user (needs "Phone" permission) |
| Password | — | FRITZ!Box password |
| Number to dial | — | e.g. `**9` (all phones), `**610` (DECT 1) |

---

## Events

The integration fires the following HA events that can be used in automations. `entry_id` is always the config entry of the sending door station.

```yaml
# Doorbell (SIP INVITE from Siedle)
event_type: siedle_doorbell
data:
  source: "sip"
  from: "..."          # From header of the INVITE
  call_id: "..."
  caller_id: "..."     # user part of the From URI
  caller_host: "..."
  button: "default"
  entry_id: "..."

# Doorbell (FCM push)
event_type: siedle_doorbell
data:
  call_id: "..."
  callee: "..."
  timestamp: "..."
  type: "CALL"
  entry_id: "..."

# Generic event: FCM
event_type: siedle_event
data:
  type: "fcm"
  event_type: "doorbell"          # other FCM message types: their lowercase name
  call_id: "..."                  # call_id, callee, timestamp only for "doorbell"
  callee: "..."
  timestamp: "..."
  raw: { ... }                    # raw FCM data
  entry_id: "..."

# Generic event: MQTT
event_type: siedle_event
data:
  type: "mqtt"
  topic: "..."
  payload: { ... }
  entry_id: "..."

# Call state changes
event_type: siedle_call_state
data:
  state: "idle" | "ringing_in" | "ringing_out" | "connected" | "recording" | "ending"
  data: { ... }
  entry_id: "..."

# DTMF action executed (only if the DTMF door opener is enabled)
event_type: siedle_dtmf_action
data:
  action: "open_door" | "toggle_light"
  code: "#"
  entry_id: "..."

# Further FCM events
event_type: siedle_call_ended          # call_id, timestamp, type: "CANCEL_CALL", entry_id
event_type: siedle_fcm_connected       # status: "connected", entry_id
event_type: siedle_fcm_disconnected    # status: "disconnected", entry_id
```

> Only if the legacy SIP listener is used as a fallback, `siedle_event` is additionally fired with `type: "sip"` (`event_type`, `from`, `call_id`) and `siedle_doorbell` carries only `source`, `from`, `call_id`, `entry_id`.

### Automation Example

```yaml
automation:
  - alias: "Doorbell Notification"
    trigger:
      - trigger: state
        entity_id: binary_sensor.<your_doorbell_entity>  # the "Türklingel" entity, ID: see Settings → Devices
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

| Service | Fields | Description |
|---------|--------|-------------|
| `siedle.open_door` | `contact_id` (optional) | Opens the door |
| `siedle.toggle_light` | `contact_id` (optional) | Toggles door light |
| `siedle.hangup_call` | — | Ends the active call (doorbell or external) |
| `siedle.activate_endpoint` | — | Activate endpoint — press doorbell! |
| `siedle.call_door` | `contact_id` (optional) | **Experimental**, audio only: starts a call to the door station without waiting for a doorbell press |

With several Siedle entries, `contact_id` selects the right door station: the service uses the entry whose door contacts contain that ID (the ID is the `contact_id` attribute of the *Türkontakt* binary sensor). Without `contact_id`, or if no entry knows it, the first loaded entry is used. `activate_endpoint` always uses the first loaded entry; `hangup_call` ends the first active call it finds.

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
    custom_components.siedle.fcm_transport: debug
    custom_components.siedle.siedle_api: debug
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
