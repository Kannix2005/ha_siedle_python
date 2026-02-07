# Changelog

Alle wichtigen Änderungen an diesem Projekt werden hier dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [3.0.0] - 2025-07-07

### Hinzugefügt
- **F1: Anruf-Timeout mit Fallback** — Konfigurierbarer Timeout pro Weiterleitungsziel (Standard: 30s). Bei Timeout wird das nächste Ziel probiert.
- **F2: Mehrere Weiterleitungsziele** — Kommaseparierte Nummern (z.B. `**620,**621,**9`), werden sequentiell durchprobiert.
- **F4: Anruf-Historie Sensor** — `sensor.siedle_anrufhistorie` speichert die letzten 50 Anrufe mit Zeitstempel, Anrufer-ID, Dauer, Aufnahmedatei und DTMF-Aktionen.
- **F6: Zeitgesteuerte Weiterleitung** — Weiterleitung nur zu bestimmten Uhrzeiten und Wochentagen aktiv. Unterstützt Mitternachtsübergang (z.B. 22:00-06:00).
- **F7: Bitte-Warten-Ansage** — Spielt eine WAV-Datei oder einen Signalton für den Besucher an der Türstation ab, während der Anruf weitergeleitet wird.
- **F8: DTMF Türöffner** — Tür öffnen (z.B. `#`) oder Licht schalten (z.B. `*`) per Telefon-Tastendruck während eines aktiven Gesprächs. RFC 4733 Parsing.
- **F9: Media Source** — Türgespräch-Aufnahmen direkt im HA Media Browser abspielen und durchsuchen.
- **F10: Diagnostics Plattform** — Vollständiger Systemstatus (SIP, MQTT, FCM, RTP, Config) für Fehlersuche über Einstellungen → Diagnose.
- **F12: Mehrere Klingeltaster** — Unterscheidung verschiedener Klingelknöpfe per SIP Header Pattern-Matching.
- **F13: Fritz!Box Click-to-Dial** — DECT-Telefone an einer Fritz!Box per TR-064 Protokoll klingeln lassen (z.B. `**9` = alle Telefone, `**610` = DECT 1).
- **F14: Kamera-Entity Stub** — Vorbereitung für zukünftige Türkamera-Integration.
- **Neue Config-Flow Seiten**: Zeitplan, DTMF, Ansage, Fritz!Box (8 Menüpunkte total)
- **Neue Entitäten**: `sensor.siedle_anrufhistorie`, `camera.siedle_turstation_kamera`
- **DTMF Event** — `siedle_dtmf_action` Event wird gefeuert wenn DTMF-Aktion ausgeführt wird

### Geändert
- Config Flow erweitert um 4 neue Options-Seiten
- SIP Manager unterstützt nun sequentielle Weiterleitungsziele und Timeout
- RTP Handler erweitert um DTMF-Erkennung (DtmfDetector) und Audio-Wiedergabe (AudioPlayer)
- `manifest.json` Version auf 3.0.0, `aiohttp` als Dependency hinzugefügt
- README mit allen neuen Features aktualisiert

## [2.1.0] - 2025-06-28

### Hinzugefügt
- **SIP-Weiterleitung funktioniert** — Türklingel wird zuverlässig an externe SIP-Telefone weitergeleitet
- **Bidirektionale Audio-Brücke** — Gegensprechen über externes SIP-Telefon (SRTP ↔ RTP)
- **B2BUA-Architektur** — Vollständige Back-to-Back User Agent Implementation für Anrufweiterleitung

### Behoben
- Call Cleanup: `_end_call()` sendet nun BYE für CONNECTED+RECORDING States und räumt STUN-Cache auf
- CANCEL-Behandlung: Korrekte 487 "Request Terminated" Antwort mit vollständigem Cleanup
- RTP-Bridge-Reuse: `setup()` ruft `stop()` auf, wenn Bridge noch läuft; SRTP-Kontexte werden zurückgesetzt
- Duplikat-Thread: Entfernte doppelte B→A Thread-Erstellung (Copy-Paste Bug)
- Active Call Guard: Neue INVITEs beenden korrekt den vorherigen Anruf bevor ein neuer gestartet wird
- CSeq-basierte Antwort-Filterung verhindert OPTIONS/REGISTER 401/407 Spam

## [2.0.0] - 2025-02-05

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
- Klingelerkennung um SIP INVITE erweitert (zusätzlich zu FCM)
- Architektur überarbeitet für bessere Wartbarkeit
- Version auf 2.0.0 erhöht wegen Breaking Changes

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
