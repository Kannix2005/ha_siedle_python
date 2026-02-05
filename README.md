# Siedle Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/Kannix2005/ha_siedle_python.svg)](https://github.com/Kannix2005/ha_siedle_python/releases)
[![GitHub License](https://img.shields.io/github/license/Kannix2005/ha_siedle_python.svg)](LICENSE)
[![Validate](https://github.com/Kannix2005/ha_siedle_python/actions/workflows/validate.yml/badge.svg)](https://github.com/Kannix2005/ha_siedle_python/actions/workflows/validate.yml)

Eine vollständige Home Assistant Integration für Siedle IQ Türstationen (SUS2).

## Features

### Grundfunktionen
- 🚪 **Türöffner** - Öffne die Tür direkt aus Home Assistant
- 💡 **Türlicht** - Schalte das Licht an der Türstation
- 🔔 **Klingelerkennung** - Binary Sensor der bei Klingeln aktiviert wird (via SIP)
- 📊 **Status-Sensoren** - SIP-Verbindung, Anrufstatus, Türkontakte
- 🔒 **Lock Entity** - Tür als Schloss-Entity in HA

### SIP & Telefonie (NEU in v2.0)
- 📞 **SIP-Klingelerkennung** - Zuverlässige Erkennung via SIP INVITE
- 📱 **Anrufweiterleitung** - Leite Türklingel an externe SIP-Server weiter (z.B. FritzBox)
- 🔊 **Audio-Brücke** - Bidirektionale Audioübertragung zwischen Siedle und externem Telefon
- 🎙️ **Automatische Aufnahme** - Zeichne Türgespräche als WAV-Datei auf
- ❌ **Auflegen-Button** - Beende aktive Anrufe direkt aus Home Assistant

## Installation

### HACS (empfohlen)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Kannix2005&repository=ha_siedle_python&category=integration)

Oder manuell:
1. HACS öffnen
2. "Custom repositories" hinzufügen:
   - URL: `https://github.com/Kannix2005/ha_siedle_python`
   - Kategorie: Integration
3. "Siedle" suchen und installieren
4. Home Assistant neu starten

### Manuell

1. Den `custom_components/siedle` Ordner nach `config/custom_components/siedle` kopieren
2. Home Assistant neu starten

## Einrichtung

1. In Home Assistant zu "Einstellungen" → "Geräte & Dienste" → "Integration hinzufügen"
2. "Siedle" suchen
3. QR-Code von der Siedle App scannen oder manuell eingeben
4. Die Türklingel drücken um die Verbindung zu bestätigen

### QR-Code Format

Der QR-Code enthält folgende Informationen:
```json
{
  "endpointSetupKey": "...",
  "endpointTransferSecret": "..."
}
```

## Entitäten

Nach der Einrichtung werden folgende Entitäten erstellt:

### Lock & Switch
| Entity | Typ | Beschreibung |
|--------|-----|--------------|
| `lock.siedle_door` | Lock | Tür als Schloss (unlock = öffnen) |
| `switch.siedle_door_light` | Switch | Türlicht schalten |

### Binary Sensors
| Entity | Typ | Beschreibung |
|--------|-----|--------------|
| `binary_sensor.siedle_turklingel` | Binary Sensor | Wird "on" wenn geklingelt wird |
| `binary_sensor.siedle_sip_verbindung` | Binary Sensor | SIP-Verbindungsstatus |

### Sensoren
| Entity | Typ | Beschreibung |
|--------|-----|--------------|
| `sensor.siedle_anrufstatus` | Sensor | Aktueller Anrufstatus (idle/ringing/active/...) |
| `sensor.siedle_sip_status` | Sensor | Detaillierter SIP-Status |
| `sensor.siedle_letzte_aufnahme` | Sensor | Pfad zur letzten Aufnahme |

### Buttons
| Entity | Typ | Beschreibung |
|--------|-----|--------------|
| `button.siedle_auflegen` | Button | Aktiven Anruf beenden |
| `button.siedle_turoeffner` | Button | Tür öffnen |
| `button.siedle_turlicht` | Button | Türlicht einschalten |

## Konfiguration

Die Integration kann über die Optionen konfiguriert werden (Einstellungen → Geräte & Dienste → Siedle → Konfigurieren).

### Allgemein
- **Klingel-Reset-Zeit** - Zeit in Sekunden bis der Klingelsensor zurückgesetzt wird (Standard: 30)
- **Verbindungstimeout** - Timeout für API-Anfragen in Sekunden (Standard: 30)

### Externer SIP Server

Ermöglicht die Weiterleitung von Türklingeln an einen externen SIP-Server (z.B. FritzBox, Asterisk):

| Option | Beschreibung |
|--------|--------------|
| **Aktiviert** | Externen SIP-Server aktivieren |
| **Host** | IP oder Hostname (z.B. `192.168.178.1` für FritzBox) |
| **Port** | SIP-Port (Standard: 5060) |
| **Benutzername** | SIP-Benutzername |
| **Passwort** | SIP-Passwort |
| **Transport** | UDP, TCP oder TLS |

### Anrufweiterleitung

| Option | Beschreibung |
|--------|--------------|
| **Aktiviert** | Weiterleitung aktivieren |
| **Zielrufnummer** | Nummer die angerufen wird (z.B. `**9` für FritzBox-Rundruf) |
| **Absendernummer** | Wird dem Angerufenen angezeigt |
| **Auto-Answer** | Anruf automatisch annehmen (für Audio-Brücke erforderlich) |

### Aufzeichnung

| Option | Beschreibung |
|--------|--------------|
| **Aktiviert** | Automatische Aufnahme aktivieren |
| **Max. Dauer** | Maximale Aufnahmedauer in Sekunden (Standard: 120) |
| **Speicherpfad** | Verzeichnis für WAV-Dateien (Standard: `/config/siedle_recordings`) |

## Klingelerkennung

Die Klingelerkennung funktioniert über SIP - wenn jemand klingelt, sendet die Siedle-Anlage einen SIP INVITE. Dies ist die zuverlässigste Methode.

### Events in Home Assistant

Folgende Events werden gefeuert:

```yaml
# Bei jedem Siedle-Event
event_type: siedle_event
data:
  type: "fcm" oder "mqtt"
  event_type: "doorbell"
  title: "Klingel"
  body: "Jemand klingelt"
  entry_id: "..."

# Speziell bei Klingeln
event_type: siedle_doorbell
data:
  title: "..."
  body: "..."
  entry_id: "..."
```

### Automation Beispiel

```yaml
automation:
  - alias: "Klingel-Benachrichtigung"
    trigger:
      - platform: state
        entity_id: binary_sensor.siedle_turklingel
        to: "on"
    action:
      - service: notify.mobile_app
        data:
          message: "Jemand klingelt an der Tür!"
          data:
            push:
              sound: "default"
              interruption-level: "time-sensitive"
```

## API Architektur

Die Integration kommuniziert mit dem Siedle SUS2 Server:

```
┌─────────────────┐     HTTPS/REST      ┌──────────────────┐
│   Home         │◄───────────────────►│  sus2.siedle.com │
│   Assistant    │                      │  (REST API)      │
│                │                      │                  │
│                │     SIP/TLS          │  sus2-sip...     │
│                │◄───────────────────►│  (Klingel/Anruf) │
│                │                      │                  │
│                │     SIP/UDP          │  FritzBox/       │
│                │◄───────────────────►│  Asterisk        │
│                │                      │  (Weiterleitung) │
└─────────────────┘                     └──────────────────┘
```

### Endpunkte

| Endpoint | Methode | Beschreibung |
|----------|---------|--------------|
| `/api/endpoint/v1/endpoint` | POST | Endpoint registrieren |
| `/oauth/token` | POST | OAuth Token anfordern |
| `/api/endpoint/v1/endpoint/config` | GET | Konfiguration (MQTT, SIP Credentials) |
| `/api/endpoint/v1/endpoint/contacts` | GET | Türkontakte abrufen |
| `/api/endpoint/v1/endpoint/contacts/{id}/doorOpenerRequest` | POST | Tür öffnen (HMAC signiert) |
| `/api/endpoint/v1/endpoint/contacts/{id}/doorLightRequest` | POST | Licht schalten (HMAC signiert) |

### HMAC Signatur

Tür- und Licht-Anfragen müssen mit HMAC-SHA256 signiert werden:

```
message = action + connectionId + timestamp + contactId
signature = HMAC-SHA256(sharedSecret, message)
```

Das `sharedSecret` wird aus der `setupData` mit AES-CBC und dem `transferSecret` aus dem QR-Code entschlüsselt.

## Debugging

### Logs aktivieren

```yaml
logger:
  default: info
  logs:
    custom_components.siedle: debug
    custom_components.siedle.sip_manager: debug
    custom_components.siedle.rtp_handler: debug
```

## Services

Die Integration stellt folgende Services bereit:

| Service | Beschreibung |
|---------|--------------|
| `siedle.open_door` | Öffnet die Tür |
| `siedle.toggle_light` | Schaltet das Türlicht |
| `siedle.hangup_call` | Beendet den aktiven Anruf |

### Service-Aufruf Beispiel

```yaml
# In einer Automation
action:
  - service: siedle.hangup_call
    data:
      entry_id: "abc123..."  # Optional, bei mehreren Siedle-Instanzen
```

## Bekannte Einschränkungen

1. **Audio-Qualität** - Die RTP-Brücke unterstützt PCMU/PCMA (G.711). Andere Codecs werden nicht unterstützt.
2. **Aufnahmen** - Aufnahmen werden als 8kHz Mono WAV gespeichert (entsprechend G.711)
3. **Externer SIP** - Der externe SIP-Server muss vom HA-Server aus erreichbar sein

## Support

- 🐛 **Bug melden**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)
- 💡 **Feature anfragen**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)
- 📖 **Changelog**: [CHANGELOG.md](CHANGELOG.md)

## Lizenz

GPL-3.0 License - siehe [LICENSE](LICENSE)