# Siedle Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/Kannix2005/ha_siedle_python.svg)](https://github.com/Kannix2005/ha_siedle_python/releases)
[![GitHub License](https://img.shields.io/github/license/Kannix2005/ha_siedle_python.svg)](LICENSE)

🇩🇪 Deutsche Version | **[🇬🇧 English Version](README_EN.md)**

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
- 📡 **Fritz!Box Click-to-Dial** — DECT-Telefone über FRITZ!Box klingeln lassen per TR-064 (F13)
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
3. Du wirst zu einer QR-Scanner-Seite weitergeleitet, die direkt von deiner Home Assistant-Instanz bereitgestellt wird:
   - **Mit Kamera** (HTTPS erforderlich): Wenn dein HA über HTTPS erreichbar ist (z.B. Nabu Casa, Reverse Proxy), kann die Handy-Kamera den QR-Code direkt im Browser scannen.
   - **Manuelle Eingabe**: Falls die Kamera nicht funktioniert (z.B. HTTP-Only-Setup, Desktop-Browser, keine Kamera-Berechtigung), bietet die Scanner-Seite ein manuelles Eingabefeld. Scanne den QR-Code einfach mit einer beliebigen QR-Scanner-App auf deinem Handy, kopiere den Textinhalt und füge ihn in das Feld ein.
4. Scanne den QR-Code von der Siedle App (mit dem zweiten Gerät oder der Webcam)
5. Die Daten werden automatisch an HA übermittelt

### Schritt 3: Endpoint aktivieren

1. Nachdem die QR-Daten übertragen wurden, fordert HA dich auf: **"Drücke jetzt die Türklingel"**
2. Drücke die physische Klingel an der Türstation
3. Die Integration erkennt den Push und aktiviert den Endpoint beim Siedle-Server

### Schritt 4: Optionen konfigurieren

Nach erfolgreicher Einrichtung kannst du in den Integrations-Optionen folgendes aktivieren:
- **Aufzeichnung**: Zeichnet das Türgespräch als WAV auf, Größe der Anruf-Historie
- **Allgemein**: FCM Push, Gerätename, MQTT und SIP an/aus
- **Externer SIP-Server**: Anrufweiterleitung an FRITZ!Box, Asterisk & Co.
- **Anrufweiterleitung**: Türklingel an externes SIP-Telefon mit bidirektionalem Audio (Ziele, Timeout, Auto-Answer)
- **Zeitsteuerung Weiterleitung**: Weiterleitung nur zu bestimmten Uhrzeiten/Wochentagen
- **DTMF Türöffner**: Tür öffnen / Licht schalten per Tastendruck während des Gesprächs
- **Bitte-warten-Ansage** und **FRITZ!Box Integration**


## Entitäten

Alle Entitäten gehören zu einem Gerät mit dem Namen `Siedle <erste 8 Zeichen der Endpoint-ID>` (außer der Kamera, die kein Gerät hat). Die Entitätsnamen sind feste deutsche Namen aus dem Code (nicht übersetzt). Home Assistant bildet die Entity-ID aus Gerätename und Entitätsname; die genaue ID hängt daher von deiner Installation ab — du findest sie unter **Einstellungen → Geräte & Dienste → Siedle → Geräte**. Die Tabellen nennen deshalb Entitätsnamen statt IDs.

### Binärsensoren
| Entitätsname | Beschreibung |
|--------------|--------------|
| Türklingel | Wird kurzzeitig "on" (5 Sek.) wenn geklingelt wird (reagiert auf das Event `siedle_doorbell`, FCM-Klingel-Events und MQTT-Topics, die nach Klingel aussehen) |
| MQTT Verbindung | MQTT-Verbindungsstatus zum Siedle-Server |
| FCM Push Verbindung | FCM Push-Verbindungsstatus |
| Türkontakt `<Rufnummer>` | Einer pro Türkontakt: "on", wenn der Kontakt einen Türöffner hat. Attribute: `contact_id`, `call_number`, `callable`, `has_camera`, `has_door_opener`, `has_door_light` |

### Sensoren
| Entitätsname | Beschreibung |
|--------------|--------------|
| Anrufstatus | Aktueller Anrufstatus: `Bereit` (idle) / `Verbunden` (connected) / `Aufnahme` (recording); andere interne Zustände (`ringing_in`, `ringing_out`, `ending`) erscheinen als Rohtext. Nur bei aktiviertem SIP. Attribute: `call_active` sowie Daten der letzten Statusänderung |
| SIP Status | `Beide verbunden` / `Siedle verbunden` / `Extern verbunden` / `Getrennt`. Attribute: `siedle_sip_registered`, `external_sip_registered` |
| MQTT Status | `Verbunden` / `Getrennt`. Attribut: `mqtt_connected` |
| Letzte Aufnahme | Zeitstempel der letzten Aufnahme. Attribute: `filepath`, `filesize`, `media_url` (nur bei Pfaden unter `www/`) |
| Anruf-Historie | Anzahl gespeicherter Anrufe. Attribute: `total_calls`, `calls_today`, `last_calls` (letzte 10, neueste zuerst: `timestamp`, `from`, `caller_id`, `call_id`, `source`, `answered`, `duration_seconds`, `recording_file`, `dtmf_door_opened`), `active_call` |

### Buttons
| Entitätsname | Beschreibung |
|--------------|--------------|
| Tür öffnen | Tür öffnen |
| Licht | Türlicht einschalten |
| Auflegen | Aktiven Anruf beenden (nur bei aktiviertem SIP) |

### Kamera
| Entitätsname | Beschreibung |
|--------------|--------------|
| Türstation Kamera | Nur Platzhalter: kein Videostream und derzeit auch nie ein Bild |

---

## Konfigurationsoptionen

Über **Einstellungen → Geräte & Dienste → Siedle → Konfigurieren**:

### Aufnahme

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Automatische Aufnahme bei Türklingel |
| Max. Dauer | 30 Sek. | Maximale Aufnahmedauer (5–300 Sek.) |
| Speicherpfad | `www/siedle_recordings` | Verzeichnis für WAV-Dateien (relativ zum HA-Konfigurationsordner) |
| Größe der Anruf-Historie | 50 | Anzahl der Anrufe, die der Sensor *Anruf-Historie* behält (10–500) |

> ⚠️ **Hinweis:** Die Aufnahme von Gesprächen an der Tür kann rechtlich problematisch sein. Bitte stelle sicher, dass du die lokalen Datenschutzgesetze einhältst (z.B. DSGVO, Bundesdatenschutzgesetz).

Bei aktivierter Aufnahme wird der Anruf automatisch angenommen (Auto-Answer), die Audio-Daten werden per SRTP empfangen, entschlüsselt und als WAV-Datei gespeichert. Nach Ablauf der Aufnahmedauer wird der Anruf automatisch beendet (Auto-Hangup).

### Allgemein / FCM Push-Benachrichtigungen

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | An | FCM-basierte Klingelerkennung |
| Gerätename | HA Standortname | Name der in der Siedle App angezeigt wird |
| MQTT | An | MQTT-Verbindung für den Gerätestatus |
| SIP | An | SIP-Registrierung für Klingelerkennung und Anrufverarbeitung (ohne sie gibt es keine Anrufstatus-/Auflegen-Entitäten und keine Weiterleitung) |

FCM ist die **primäre und zuverlässigste Methode** zur Klingelerkennung. Die Integration emuliert ein Android-Gerät und empfängt Firebase Cloud Messages direkt.

> ⚠️ **Hinweis zu Push-Limits:** Die Siedle-Server senden bei mehrmaligem Klingeln innerhalb von **10 Minuten nur eine einzige Push-Nachricht**. Dies ist eine Limitierung des Siedle-Systems, nicht der Integration. Die Integration erkennt alle Klingelvorgänge über SIP INVITE — nur die FCM-Push-Benachrichtigung wird gedrosselt.

### Externer SIP-Server

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Externen SIP-Server für Anrufweiterleitung aktivieren |
| Host | — | IP oder Hostname (z.B. `192.168.178.1` für FritzBox) |
| Port | 5060 | SIP-Port (1–65535) |
| Benutzername | — | SIP-Benutzername für REGISTER |
| Passwort | — | SIP-Passwort |
| Transport | UDP | UDP, TCP oder TLS |

Server, die für den weitergeleiteten Anruf eine Digest-Anmeldung verlangen (`401`/`407`, z.B. eine als IP-Türsprechanlage eingerichtete FRITZ!Box), werden seit 3.1.5 unterstützt.

### Anrufweiterleitung

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Weiterleitung bei Klingeln |
| Zielrufnummer | — | z.B. `**9` (FritzBox Rundruf); mehrere Ziele kommasepariert (z.B. `**620,**621`), werden nacheinander versucht |
| Erlaubte Anrufernummer | — | Filter für Anrufe **vom** externen SIP-Server **zur** Tür: Ein eingehender Anruf wird nur angenommen, wenn diese Nummer in seinem From-Header vorkommt, sonst wird er mit `403` abgewiesen. Leer = jeder Anrufer wird angenommen. Es wird keine Rufnummer gesendet. |
| Timeout | 30 Sek. | Klingeldauer pro Ziel, bevor das nächste versucht wird (5–120 Sek.) |
| Auto-Answer | Aus | Türstation automatisch annehmen |

### Zeitsteuerung Weiterleitung

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Nur im Zeitplan weiterleiten (sonst immer, wenn die Weiterleitung aktiv ist) |
| Start / Ende | `00:00` / `23:59` | Zeitraum `HH:MM`; ein Zeitraum über Mitternacht (z.B. `22:00`–`06:00`) wird unterstützt |
| Aktive Tage | Mo–So | Wochentage, an denen weitergeleitet wird |

### DTMF Türöffner

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | Tastendrücke während eines weitergeleiteten Anrufs auswerten |
| Türcode | `#` | Code, der die Tür öffnet (einzelne Taste oder Folge, z.B. `1234#`) |
| Lichtcode | `*` | Code, der das Türlicht schaltet (z.B. `*` oder `56*`) |

Tastendrücke werden sowohl als RFC-4733-Telefonereignisse im RTP-Strom als auch als SIP INFO (`application/dtmf-relay`, `application/dtmf`) erkannt — Letzteres nutzt die FRITZ!Box. Meldet der Server eine Taste auf beiden Wegen, zählt sie einmal. Mehrstellige Codes werden nach 3 Sekunden Eingabepause ausgewertet; die eingegebene Folge muss mit dem Code enden. Jede ausgeführte Aktion löst das Event `siedle_dtmf_action` aus.

### Bitte-warten-Ansage

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | "Bitte warten"-Ansage abspielen |
| WAV-Datei | leer | Pfad zu einer WAV-Datei (8 kHz, 16 Bit, mono); leer = integrierter Signalton |

> ℹ️ Die Option wird gespeichert, der aktuelle Code spielt die Ansage aber noch nicht ab (keine Stelle ruft die Wiedergabefunktion auf).

### FRITZ!Box Integration

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| Aktiviert | Aus | FRITZ!Box-Telefon bei Klingeln per TR-064 klingeln lassen (30 Sek. Klingeln, dann Auflegen) |
| Host | `fritz.box` | Adresse der FRITZ!Box |
| Benutzername | `admin` | FRITZ!Box-Benutzer (braucht Berechtigung "Telefonie") |
| Passwort | — | FRITZ!Box-Passwort |
| Zielnummer | — | z.B. `**9` (alle Telefone), `**610` (DECT 1) |

---

## Events

Die Integration feuert folgende HA-Events, die in Automationen verwendet werden können. `entry_id` ist immer der Config-Eintrag der sendenden Türstation.

```yaml
# Türklingel (SIP INVITE von Siedle)
event_type: siedle_doorbell
data:
  source: "sip"
  from: "..."          # From-Header des INVITE
  call_id: "..."
  caller_id: "..."     # Benutzerteil der From-URI
  caller_host: "..."
  button: "default"
  entry_id: "..."

# Türklingel (FCM-Push)
event_type: siedle_doorbell
data:
  call_id: "..."
  callee: "..."
  timestamp: "..."
  type: "CALL"
  entry_id: "..."

# Allgemeines Event: FCM
event_type: siedle_event
data:
  type: "fcm"
  event_type: "doorbell"          # andere FCM-Nachrichtentypen: ihr Name in Kleinbuchstaben
  call_id: "..."                  # call_id, callee, timestamp nur bei "doorbell"
  callee: "..."
  timestamp: "..."
  raw: { ... }                    # rohe FCM-Daten
  entry_id: "..."

# Allgemeines Event: MQTT
event_type: siedle_event
data:
  type: "mqtt"
  topic: "..."
  payload: { ... }
  entry_id: "..."

# Bei Anrufstatus-Änderungen
event_type: siedle_call_state
data:
  state: "idle" | "ringing_in" | "ringing_out" | "connected" | "recording" | "ending"
  data: { ... }
  entry_id: "..."

# DTMF-Aktion ausgeführt (nur bei aktiviertem DTMF Türöffner)
event_type: siedle_dtmf_action
data:
  action: "open_door" | "toggle_light"
  code: "#"
  entry_id: "..."

# Weitere FCM-Events
event_type: siedle_call_ended          # call_id, timestamp, type: "CANCEL_CALL", entry_id
event_type: siedle_fcm_connected       # status: "connected", entry_id
event_type: siedle_fcm_disconnected    # status: "disconnected", entry_id
```

> Nur wenn als Fallback der alte SIP-Listener läuft, wird zusätzlich `siedle_event` mit `type: "sip"` (`event_type`, `from`, `call_id`) gefeuert, und `siedle_doorbell` enthält nur `source`, `from`, `call_id`, `entry_id`.

### Automation-Beispiel

```yaml
automation:
  - alias: "Klingel-Benachrichtigung"
    trigger:
      - trigger: state
        entity_id: binary_sensor.<deine_klingel_entitaet>  # die Entität "Türklingel", ID: siehe Einstellungen → Geräte
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

| Service | Felder | Beschreibung |
|---------|--------|--------------|
| `siedle.open_door` | `contact_id` (optional) | Öffnet die Tür |
| `siedle.toggle_light` | `contact_id` (optional) | Schaltet das Türlicht |
| `siedle.hangup_call` | — | Beendet den aktiven Anruf (Klingel oder extern) |
| `siedle.activate_endpoint` | — | Endpoint aktivieren — Klingel drücken! |
| `siedle.call_door` | `contact_id` (optional) | **Experimentell**, nur Audio: startet einen Anruf zur Türstation, ohne auf einen Klingeldruck zu warten |

Bei mehreren Siedle-Einträgen wählt `contact_id` die richtige Türstation: Der Service nutzt den Eintrag, dessen Türkontakte diese ID enthalten (die ID steht im Attribut `contact_id` des Binärsensors *Türkontakt*). Ohne `contact_id` oder wenn kein Eintrag die ID kennt, wird der erste geladene Eintrag verwendet. `activate_endpoint` nutzt immer den ersten geladenen Eintrag; `hangup_call` beendet den ersten aktiven Anruf, den es findet.

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
    custom_components.siedle.fcm_transport: debug
    custom_components.siedle.siedle_api: debug
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