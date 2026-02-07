# Siedle Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/Kannix2005/ha_siedle_python.svg)](https://github.com/Kannix2005/ha_siedle_python/releases)
[![GitHub License](https://img.shields.io/github/license/Kannix2005/ha_siedle_python.svg)](LICENSE)

Eine vollständige Home Assistant Integration für **Siedle IQ Türstationen (SUS2)** — vollständig reverse-engineered aus der offiziellen Siedle App.

## Features

- 🚪 **Türöffner** — Öffne die Tür direkt aus Home Assistant
- 💡 **Türlicht** — Schalte das Licht an der Türstation
- 🔔 **Klingelerkennung** — Sofortige Erkennung via FCM Push-Benachrichtigungen und SIP INVITE
- 🎙️ **Audio-Aufnahme** — Automatische Aufzeichnung des Türgesprächs als WAV-Datei (SRTP → PCM)
- 📱 **SIP-Weiterleitung** — Türklingel an ein externes SIP-Telefon weiterleiten (z.B. FritzBox, Asterisk, MicroSIP)
- 🔊 **Bidirektionale Audio-Brücke** — Gegensprechen mit der Tür über externes SIP-Telefon (SRTP ↔ RTP)
- ⏱️ **Anruf-Timeout & Fallback** — Automatischer Timeout pro Weiterleitungsziel, dann nächstes Ziel (F1)
- 📞 **Mehrere Weiterleitungsziele** — Kommaseparierte Nummern, wird sequentiell durchprobiert (F2)
- 📊 **Anruf-Historie** — Sensor mit den letzten X Anrufen inkl. Zeitstempel, Anrufer, Dauer (F4)
- 🕐 **Zeitgesteuerte Weiterleitung** — Weiterleitung nur zu bestimmten Uhrzeiten/Wochentagen (F6)
- 🔈 **Bitte-Warten-Ansage** — WAV-Datei oder Signalton abspielen während Verbindungsaufbau (F7)
- 🔢 **DTMF Türöffner** — Tür per Telefon-Tastendruck (z.B. #) während Gespräch öffnen (F8)
- 🎵 **Media Source** — Aufnahmen direkt in HA Media Browser abspielen (F9)
- 🔍 **Diagnostics** — Vollständiger Systemstatus für Fehlersuche (F10)
- 🔘 **Mehrere Klingeltaster** — Unterscheidung verschiedener Türstations-Klingelknöpfe (F12)
- 📡 **Fritz!Box Click-to-Dial** — DECT-Telefone über FR!TZBox klingeln lassen per TR-064 (F13)
- 📷 **Kamera-Entity** — Stub für zukünftige Türkamera-Integration (F14)
- ❌ **Auflegen-Button** — Beende aktive Anrufe direkt aus Home Assistant
- 📊 **Status-Sensoren** — SIP, MQTT, FCM Verbindungsstatus, Anrufstatus, Türkontakte
- 🔒 **Sichere Kommunikation** — SIP über TLS, Audio über SRTP (AES-CM-128-HMAC-SHA1-80)

---

## Voraussetzungen

- Ein **Siedle IQ System (SUS2)** mit eingerichteter Siedle App
- Home Assistant (empfohlen: aktuelle Version)
- **Netzwerk-Voraussetzungen für Audio-Aufnahme:**
  - Dein Home Assistant muss über das Internet erreichbar sein (Port-Forwarding für den RTP-Port, Standard ~45000-65000)
  - Oder: Dein Router muss 1:1 NAT / Full-Cone NAT unterstützen (OPNSense, pfSense)
  - Die Integration nutzt STUN um den externen Port automatisch zu erkennen

---

## Installation

### HACS (empfohlen)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Kannix2005&repository=ha_siedle_python&category=integration)

Oder manuell in HACS:
1. HACS öffnen → "Custom repositories" hinzufügen
2. URL: `https://github.com/Kannix2005/ha_siedle_python`, Kategorie: Integration
3. "Siedle" suchen und installieren
4. Home Assistant neu starten

### Manuell

1. Den `custom_components/siedle` Ordner nach `config/custom_components/siedle` kopieren
2. Home Assistant neu starten

---

## Einrichtung (Setup)

### Schritt 1: QR-Code aus der Siedle App scannen

> ⚠️ **Wichtig:** Du brauchst vermutlich ein **zweites Gerät** (z.B. ein Tablet oder das Handy eines Freundes), um den QR-Code von deinem Handy-Bildschirm abzuscannen. Der QR-Code wird in der Siedle App angezeigt und muss vom HA-Setup-Dialog erfasst werden.

1. Öffne die **Siedle App** auf deinem Smartphone
2. Gehe zu **Einstellungen** → **Neues Gerät hinzufügen**
3. Ein QR-Code wird angezeigt — diesen brauchst du im nächsten Schritt

### Schritt 2: Integration in Home Assistant einrichten

1. Gehe in HA zu **Einstellungen → Geräte & Dienste → Integration hinzufügen**
2. Suche nach **"Siedle"**
3. Du wirst zu einer QR-Scanner-Seite weitergeleitet
4. Scanne den QR-Code von der Siedle App (mit dem zweiten Gerät oder der Webcam)
5. Die Daten werden automatisch an HA übermittelt

### Schritt 3: Endpoint aktivieren

1. Nachdem die QR-Daten übertragen wurden, fordert HA dich auf: **"Drücke jetzt die Türklingel"**
2. Drücke die physische Klingel an der Türstation
3. Die Integration erkennt den Push und aktiviert den Endpoint beim Siedle-Server

### Schritt 4: Optionen konfigurieren

Nach erfolgreicher Einrichtung kannst du in den Integrations-Optionen folgendes aktivieren:
- **Automatische Aufnahme**: Zeichnet das Türgespräch als WAV auf
- **FCM Push**: Klingelerkennung (standardmäßig aktiv)
- **Externer SIP-Server**: Anrufweiterleitung an FritzBox, Asterisk & Co.
- **Anrufweiterleitung**: Türklingel an externes SIP-Telefon mit bidirektionalem Audio


## Entitäten

### Binary Sensors
| Entity | Beschreibung |
|--------|--------------|
| `binary_sensor.siedle_turklingel` | Wird kurzzeitig "on" wenn geklingelt wird (5 Sek.) |
| `binary_sensor.siedle_mqtt_verbindung` | MQTT-Verbindungsstatus zum Siedle-Server |
| `binary_sensor.siedle_fcm_push_verbindung` | FCM Push-Verbindungsstatus |
| `binary_sensor.siedle_turkontakt_*` | Verfügbarkeit einzelner Türkontakte |

### Sensoren
| Entity | Beschreibung |
|--------|--------------|
| `sensor.siedle_anrufstatus` | Aktueller Status: Bereit / Klingelt / Verbunden / Aufnahme |
| `sensor.siedle_sip_status` | SIP-Registrierungsstatus (Siedle + ggf. extern) |
| `sensor.siedle_mqtt_status` | MQTT-Verbindungsstatus als Text |
| `sensor.siedle_letzte_aufnahme` | Zeitstempel und Pfad der letzten Aufnahme |

### Buttons
| Entity | Beschreibung |
|--------|--------------|
| `button.siedle_turoeffner` | Tür öffnen |
| `button.siedle_turlicht` | Türlicht einschalten |
| `button.siedle_auflegen` | Aktiven Anruf beenden |

---

## Konfigurationsoptionen

Über **Einstellungen → Geräte & Dienste → Siedle → Konfigurieren**:

### Aufnahme

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Automatische Aufnahme bei Türklingel |
| Max. Dauer | 30 Sek. | Maximale Aufnahmedauer |
| Speicherpfad | `www/siedle_recordings` | Verzeichnis für WAV-Dateien |

> ⚠️ **Hinweis:** Die Aufnahme von Gesprächen an der Tür kann rechtlich problematisch sein. Bitte stelle sicher, dass du die lokalen Datenschutzgesetze einhältst (z.B. DSGVO, Bundesdatenschutzgesetz).

Bei aktivierter Aufnahme wird der Anruf automatisch angenommen (Auto-Answer), die Audio-Daten werden per SRTP empfangen, entschlüsselt und als WAV-Datei gespeichert. Nach Ablauf der Aufnahmedauer wird der Anruf automatisch beendet (Auto-Hangup).

### FCM Push-Benachrichtigungen

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | An | FCM-basierte Klingelerkennung |
| Gerätename | HA Standortname | Name der in der Siedle App angezeigt wird |

FCM ist die **primäre und zuverlässigste Methode** zur Klingelerkennung. Die Integration emuliert ein Android-Gerät und empfängt Firebase Cloud Messages direkt.

### Externer SIP-Server

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Externen SIP-Server für Anrufweiterleitung aktivieren |
| Host | — | IP oder Hostname (z.B. `192.168.178.1` für FritzBox) |
| Port | 5060 | SIP-Port |
| Benutzername | — | SIP-Benutzername für REGISTER |
| Passwort | — | SIP-Passwort |
| Transport | UDP | UDP, TCP oder TLS |

### Anrufweiterleitung

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Weiterleitung bei Klingeln |
| Zielrufnummer | — | z.B. `**9` (FritzBox Rundruf) |
| Absendernummer | — | CallerID für das externe Telefon |
| Auto-Answer | Aus | Türstation automatisch annehmen |

---

## Events

Die Integration feuert folgende HA-Events, die in Automationen verwendet werden können:

```yaml
# Bei jedem Siedle-Event (FCM, MQTT, SIP)
event_type: siedle_event
data:
  type: "fcm" | "mqtt" | "sip"
  event_type: "doorbell"
  entry_id: "..."

# Speziell bei Türklingel
event_type: siedle_doorbell
data:
  source: "sip" | "fcm"
  entry_id: "..."

# Bei Anrufstatus-Änderungen
event_type: siedle_call_state
data:
  state: "idle" | "ringing" | "connected" | "recording"
  data: { ... }
  entry_id: "..."
```

### Automation-Beispiel

```yaml
automation:
  - alias: "Klingel-Benachrichtigung"
    trigger:
      - platform: state
        entity_id: binary_sensor.siedle_turklingel
        to: "on"
    action:
      - action: notify.mobile_app
        data:
          message: "Jemand klingelt an der Tür!"
          data:
            push:
              sound: "default"
              interruption-level: "time-sensitive"
```

---

## Services

| Service | Beschreibung |
|---------|--------------|
| `siedle.open_door` | Öffnet die Tür (optional: `contact_id`) |
| `siedle.toggle_light` | Schaltet das Türlicht (optional: `contact_id`) |
| `siedle.hangup_call` | Beendet den aktiven Anruf |
| `siedle.activate_endpoint` | Endpoint aktivieren — Klingel drücken! |

---

## Technische Architektur

Diese Integration kommuniziert mit dem Siedle SUS2 Cloud-System über mehrere Protokolle:

### Kommunikationskanäle

```
┌─────────────┐        REST API (HTTPS)        ┌──────────────────┐
│             │◄──────────────────────────────►│                  │
│  Home       │      SIP/TLS (:5061)           │  Siedle Cloud    │
│  Assistant  │◄──────────────────────────────►│  (sus2.siedle.   │
│             │      SRTP (UDP, dynamisch)      │   com)           │
│             │◄──────────────────────────────►│                  │
│             │      MQTT (SSL)                │                  │
│             │◄──────────────────────────────►│                  │
│             │      FCM (Push)                │                  │
│             │◄───────────────────────────────│                  │
└─────────────┘                                └──────────────────┘
```

| Protokoll | Zweck | Details |
|-----------|-------|---------|
| **REST API** | Authentifizierung, Kontakte, Türöffner, Licht | OAuth2 via `sus2.siedle.com` |
| **SIP/TLS** | Anrufsignalisierung | Port 5061, Client-Zertifikat nicht erforderlich |
| **SRTP** | Audio-Übertragung (verschlüsselt) | AES_CM_128_HMAC_SHA1_80, PCMA/8000, RFC 4568 (SDES) |
| **MQTT** | Gerätestatus, Events | TLS, Benachrichtigungen über Statusänderungen |
| **FCM** | Push-Klingelerkennung | Firebase Cloud Messaging, emuliertes Android-Gerät |

### SIP & Audio im Detail

Die SIP-Verbindung ist das Herzstück der Anruf- und Aufnahmefunktion:

1. **Registrierung:** Die Integration registriert sich per SIP REGISTER bei `sus2-sip.siedle.com:5061` (TLS)
2. **Eingehender Anruf:** Bei einem Klingeln sendet Siedle einen SIP INVITE
3. **Annahme:** Die Integration antwortet mit `100 Trying`, dann `200 OK` mit SDP
4. **Audio:** SRTP-verschlüsselte Audio-Daten (PCMA/G.711a, 8kHz) werden empfangen
5. **Aufnahme:** Die SRTP-Pakete werden entschlüsselt und als WAV-Datei gespeichert
6. **Beenden:** Nach Ablauf der Aufnahmedauer wird automatisch ein SIP BYE gesendet

#### NAT-Traversal

Da Home Assistant typischerweise hinter einem NAT-Router steht, implementiert die Integration:

- **STUN** (RFC 5389): Ermittelt die öffentliche IP und den externen Port vom tatsächlichen RTP-Socket
- **Via `received=` Parsing**: Erkennt die von Siedle gesehene öffentliche IP aus dem SIP-Header
- **NAT Punch-Through**: Sendet leere PCMA-Pakete um die NAT-Zuordnung zu öffnen
- **RTP Keepalive**: Kontinuierliche Stille-Pakete (alle 20ms) halten die NAT-Zuordnung offen
- **Multi-Via Header**: Alle Via-Header werden korrekt in SIP-Antworten kopiert (RFC 3261)
- **Record-Route**: Alle Record-Route-Header werden aus dem INVITE übernommen

#### SRTP-Verschlüsselung

- **Algorithmus:** AES_CM_128_HMAC_SHA1_80 (RFC 3711)
- **Schlüsselaustausch:** SDES via SDP (RFC 4568) — jede Seite generiert ihren eigenen Master Key
- **Key Derivation:** SRTP Key Derivation Function mit label-basierten Session Keys
- **Authentifizierung:** HMAC-SHA1, 80-bit Tag an jedem Paket

---

## Debugging

### Logs aktivieren

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

### Häufige Probleme

| Problem | Lösung |
|---------|--------|
| Kein Audio in Aufnahme | NAT-Konfiguration prüfen — Router muss UDP-Pakete durchlassen. Logs auf STUN-Ergebnisse prüfen. |
| FCM verbindet nicht | FCM braucht ~10-30 Sek. zum Starten. Token-Refresh passiert automatisch. |
| SIP registriert nicht | TLS-Verbindung zu `sus2-sip.siedle.com:5061` prüfen. Firewall-Regeln checken. |
| Türöffner funktioniert nicht | `sharedSecret` muss korrekt entschlüsselt sein — im Log nach "Restored decrypted sharedSecret" suchen. |
| Aufnahme bricht sofort ab | Prüfe ob der RTP-Port extern erreichbar ist. STUN-Log zeigt den erwarteten Port. |

### Nützliche Log-Meldungen

```
# Erfolgreiche SIP-Registrierung:
"Siedle SIP registered successfully"

# SRTP Schlüssel generiert:
"Generated local SRTP crypto line"

# Audio-Pakete empfangen:
"Received N audio bytes from Siedle, decrypted M samples"

# NAT-Erkennung:
"STUN discovered external address: x.x.x.x:yyyyy"
"Public IP from SIP Via received=: x.x.x.x"
```

---

## Bekannte Einschränkungen

- **Keine Video-Unterstützung:** Siedle SUS2 überträgt kein Video über SIP — das Kamerabild wird nur in der offiziellen App angezeigt.
- **Nur ein aktiver Anruf:** Die Integration unterstützt nur einen gleichzeitigen Anruf.
- **Cloud-Abhängigkeit:** Alle Kommunikation läuft über Siedle Cloud-Server — kein lokaler Fallback möglich.

---

## Support

- 🐛 **Bug melden**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)
- 💡 **Feature anfragen**: [GitHub Issues](https://github.com/Kannix2005/ha_siedle_python/issues)

## Lizenz

GPL-3.0 License — siehe [LICENSE](LICENSE)