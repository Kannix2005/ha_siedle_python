# Changelog

Alle wichtigen Änderungen an diesem Projekt werden hier dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [2.0.0] - 2026-02-05

### Hinzugefügt
- **SIP-Klingelerkennung** - Zuverlässige Erkennung von Türklingeln via SIP INVITE
- **Externer SIP-Server** - Unterstützung für FritzBox, Asterisk und andere SIP-Server
- **Anrufweiterleitung** - Leite Türklingel automatisch an externe Telefone weiter
- **Audio-Brücke** - Bidirektionale Audioübertragung zwischen Siedle und externem Telefon
- **Automatische Aufnahme** - Zeichne Türgespräche als WAV-Datei auf
- **Auflegen-Button** - Beende aktive Anrufe direkt aus Home Assistant
- **Neue Sensoren**:
  - `sensor.siedle_anrufstatus` - Aktueller Anrufstatus
  - `sensor.siedle_sip_status` - SIP-Verbindungsstatus
  - `sensor.siedle_letzte_aufnahme` - Pfad zur letzten Aufnahme
- **Neue Buttons**:
  - `button.siedle_auflegen` - Anruf beenden
  - `button.siedle_turoeffner` - Tür öffnen
  - `button.siedle_turlicht` - Licht einschalten
- **Options Flow** mit 4 Kategorien:
  - Allgemeine Einstellungen
  - Externer SIP-Server
  - Anrufweiterleitung
  - Aufzeichnung
- **Service** `siedle.hangup_call` zum Beenden von Anrufen

### Geändert
- Klingelerkennung von FCM/MQTT auf SIP umgestellt (zuverlässiger)
- Architektur überarbeitet für bessere Wartbarkeit
- Version auf 2.0.0 erhöht wegen Breaking Changes

### Entfernt
- MQTT-basierte Klingelerkennung (durch SIP ersetzt)
- FCM Push-Benachrichtigungen (durch SIP ersetzt)
- `paho-mqtt` Abhängigkeit entfernt

## [1.1.0] - 2025-01-15

### Hinzugefügt
- MQTT-Verbindung für Statusupdates
- FCM Push-Benachrichtigungen für Klingelerkennung
- Binary Sensor für Klingelstatus
- Events `siedle_event` und `siedle_doorbell`

### Geändert
- Verbesserte Fehlerbehandlung bei API-Aufrufen
- Timeout-Konfiguration hinzugefügt

## [1.0.0] - 2025-01-01

### Hinzugefügt
- Initiale Release
- Türöffner (Lock Entity)
- Türlicht (Switch Entity)
- QR-Code Scanner für einfache Einrichtung
- HMAC-signierte API-Anfragen
- Config Flow für UI-basierte Einrichtung
