# Changelog

Alle wichtigen Änderungen an diesem Projekt werden hier dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [3.1.2] - 2026-08-05

### Behoben
- **`Error parsing SIP message: invalid literal for int()`**: Der Parser hielt jede Zeile, die mit `SIP/2.0` beginnt, für eine Statuszeile — auch einen Via-Header (`SIP/2.0/UDP host:port;rport=…`). Der Versuch, daraus einen Statuscode zu lesen, warf eine Ausnahme, und die Nachricht wurde als ERROR verworfen. Erkannt wird jetzt nur noch eine echte Statuszeile (`SIP/2.0 <dreistelliger Code> [Grund]`); Bruchstücke werden auf Debug-Ebene protokolliert statt als Fehler.
- **Bruchstücke wurden als Anfragen fehlgedeutet**: Beginnt ein Bruchstück mit einer Header-Zeile, übernahm der Parser deren erstes Wort als SIP-Methode (`Content-Length:` als Methode). Die Nachricht wurde damit an die Rückrufe weitergereicht und traf dort als vermeintliche Antwort ohne Statuscode auf einen Vergleich mit `>= 400` — Ergebnis: `'>=' not supported between instances of 'NoneType' and 'int'`. Eine Anfragezeile muss jetzt der Form aus RFC 3261 entsprechen (`Methode SP URI SP SIP/2.0`); alles andere wird verworfen, bevor es weitergereicht wird. Die beiden Statuscode-Vergleiche sind zusätzlich gegen `None` abgesichert.

### Bekannt
- Die eigentliche Quelle solcher Bruchstücke ist die fehlende Nachrichtenrahmung auf TCP-Verbindungen: `recv()` liefert dort keine Nachrichtengrenzen, sodass ein Lesevorgang mitten in einer Nachricht beginnen oder zwei Nachrichten zusammenfassen kann. Das betrifft nur den externen SIP-Anschluss mit `transport: tcp` und tritt selten auf (zweimal an einem Tag). Eine saubere Rahmung über `Content-Length` steht aus.

## [3.1.1] - 2026-08-04

### Behoben
- **Der FCM-Watchdog riss gesunde Verbindungen ab.** Er wertete 30 Minuten ohne FCM-Verkehr als Fehler — bei einer Türklingel ist genau das der Normalzustand. In der Praxis verband er sich dadurch mehrmals pro Nacht grundlos neu (im Log: „no FCM traffic for 1800s — reconnecting"). Maßgeblich ist jetzt der Verbindungsstatus der Bibliothek; Funkstille löst erst nach 24 Stunden eine Selbstheilung aus, für den Fall eines hängenden Listeners, der sich weiterhin als verbunden meldet.
- **Neuregistrierung des Push-Tokens scheiterte mit `401 invalid_token`.** Der FCM-Handler benutzte den Zugriffstoken, den er beim Setup bekommen hatte; Siedle rotiert ihn aber. Bei jedem Reconnect schlug die Registrierung deshalb fehl und hinterließ „doorbell detection may not work". Der Token wird jetzt zum Aufrufzeitpunkt frisch aus der API gelesen.

## [3.1.0] - 2026-07-27

### Sicherheit
- **XSS in der QR-Scanner-Seite behoben**: Der Endpunkt `/api/siedle/qr_scanner` wird ohne Authentifizierung ausgeliefert und schrieb Query-Parameter ungeprüft in eingebettetes JavaScript. Ein präparierter Link konnte damit Skript im Origin von Home Assistant ausführen — also Session bzw. Token stehlen und darüber auch die Haustür öffnen. Werte werden jetzt escaped eingesetzt, und die Callback-URL wird immer aus dem Request abgeleitet statt aus einem Parameter übernommen.
- **SRTP prüft die Integrität**: Der empfangene HMAC wurde nie verifiziert („For now, skip verification"), und die RTP-Weiterleitung nahm Pakete beliebiger Absender an. Wer den Medien-Port erreichte, konnte ohne Schlüssel Audio in ein laufendes Türgespräch einspielen. Auth-Tags werden jetzt geprüft — scharf ab dem ersten gültigen Tag, damit eine abweichende Gegenstelle nicht stillschweigend die Audioverbindung verliert — und Pakete fremder Absender verworfen.
- **Kein Keystream-Reuse mehr**: Der AES-CTR-IV nutzte nur die 16-Bit-Sequenznummer und wiederholte sich nach etwa 21 Gesprächsminuten. Ein Rollover-Zähler fließt jetzt ein; in der ersten Rollover-Periode bleibt der IV unverändert, damit Gegenstellen kompatibel bleiben.
- Legacy-FCM-Zugangsdaten werden mit `0600` statt mit der Standard-Umask geschrieben, und Diagnose-Dumps schwärzen die Rufnummern der Weiterleitung.

### Behoben
- **Ein Klingeln löste bis zu zehn Anrufe aus** (#17): Wiederholte INVITEs — SIP sendet sie über UDP mehrfach, Proxys forken zusätzlich — galten jeweils als neues Klingeln, und ein bereits klingelnder weitergeleiteter Anruf wurde nie abgebrochen, sondern nur protokolliert. INVITEs werden jetzt über die Call-ID dedupliziert, und noch nicht angenommene Anrufe erhalten ein CANCEL.
- **FCM stirbt nicht mehr still** (#12): Der Listener-Thread konnte enden oder hängen bleiben, während der Status weiter „connected" meldete — Abhilfe war bisher nur, FCM manuell aus- und wieder einzuschalten. Ein Watchdog verbindet jetzt automatisch neu (mit Backoff), und `is_connected` meldet keine Verbindung mehr, deren Listener-Thread nicht läuft.
- **Token-Refresh überlastet die Siedle-API nicht mehr** (#11): Coordinator und Tastendrücke teilen sich eine Instanz und konnten den OAuth-Client gleichzeitig neu aufbauen. Der Refresh ist jetzt serialisiert und rate-limitiert; ein endgültig abgelehnter Grant wird gemerkt statt endlos wiederholt, und Home Assistant fragt über `ConfigEntryAuthFailed` nach einer neuen Anmeldung.
- **Dienste wirken auf die richtige Anlage**: `open_door` und `toggle_light` waren global registriert und zeigten auf die zuletzt geladene Konfiguration — bei zwei Türstationen öffnete sich damit unbemerkt die falsche Tür. Dienste lösen die passende Instanz jetzt über die Kontakt-ID auf, melden Fehler als `HomeAssistantError` statt als rohen Traceback und werden beim Entladen wieder abgemeldet.
- FCM-Registrierung wiederholt einen transienten `PHONE_REGISTRATION_ERROR` (danke an @arnoudkooi, #16) — ohne diesen Retry blieb FCM dauerhaft deaktiviert.

### Hinzugefügt
- **`call_door`-Dienst** (#18): startet ein Gespräch zur Türstation, ohne dass vorher geklingelt wurde. Der Dienst war seit dem ersten Commit als Platzhalter angelegt, aber nie implementiert. **Experimentell und nur Audio** — einen Video-Pfad hat die Integration bisher nicht.

- Updated integration icons

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
