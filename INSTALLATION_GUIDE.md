# Home Assistant Integration - Installationsanleitung

## Installation

Die Siedle Integration wurde erfolgreich erstellt! Hier ist, wie Sie sie installieren:

### Verzeichnisstruktur

```
custom_components/siedle/
├── __init__.py          ✅ Integration Setup
├── manifest.json        ✅ Metadata
├── config_flow.py       ✅ UI Configuration
├── const.py             ✅ Konstanten
├── lock.py              ✅ Lock Entity
├── switch.py            ✅ Switch Entity
├── sensor.py            ✅ Sensor Entity
├── services.yaml        ✅ Service Definitionen
├── strings.json         ✅ UI Texte (EN)
├── siedle_api.py        ✅ API Wrapper
├── README.md            ✅ Dokumentation
└── translations/
    ├── de.json          ✅ Deutsche Übersetzungen
    └── en.json          ✅ Englische Übersetzungen
```

## Schritt 1: Installation in Home Assistant

### Option A: Manuell

1. Kopieren Sie den Ordner `custom_components/siedle` in Ihr Home Assistant `config/custom_components/` Verzeichnis

   **Windows (lokal):**
   ```powershell
   # Wenn Home Assistant lokal läuft
   Copy-Item -Recurse custom_components\siedle "C:\Users\YourUser\homeassistant\custom_components\"
   ```

   **Home Assistant OS / Supervised:**
   ```bash
   # Via SSH oder File Editor Add-on
   # Kopieren Sie den Ordner nach /config/custom_components/siedle/
   ```

2. Starten Sie Home Assistant neu

### Option B: HACS (empfohlen)

1. Fügen Sie dieses Repository zu HACS als Custom Repository hinzu:
   - HACS → Integrationen → ⋮ (Menü) → Custom Repositories
   - Repository: `https://github.com/Kannix2005/ha_siedle_python`
   - Kategorie: Integration

2. Installieren Sie "Siedle Door Intercom"

3. Starten Sie Home Assistant neu

## Schritt 2: Integration hinzufügen

1. Gehen Sie zu **Einstellungen** → **Geräte & Dienste**

2. Klicken Sie auf **+ Integration hinzufügen**

3. Suchen Sie nach **"Siedle"**

4. Scannen Sie den QR-Code aus der Siedle App oder geben Sie die Daten manuell ein

5. **Scannen Sie den QR-Code** aus der Siedle App:
   - Öffnen Sie die **Siedle App** auf Ihrem Smartphone
   - Gehen Sie zu **Einstellungen** → **Multi-Gerät Setup**
   - Der QR-Code wird angezeigt

6. Der Scanner zeigt Ihnen die **JSON-Daten** an

7. **Kopieren Sie die JSON-Daten** (komplett mit `{` und `}`)

8. **Fügen Sie die Daten** in Home Assistant ein

9. Die Integration wird automatisch eingerichtet!

## Schritt 3: Entities verwenden

Nach erfolgreicher Einrichtung haben Sie folgende Entities:

### Lock (Schloss)
```yaml
lock.siedle_haupteingang
```
- **Unlock** = Tür öffnen
- **Lock** = Nicht unterstützt (Tür schließt automatisch)

### Switch (Licht)
```yaml
switch.siedle_haupteingang_light
```
- **Turn On** = Licht einschalten
- **Turn Off** = Licht ausschalten

### Sensor (MQTT Status)
```yaml
sensor.siedle_mqtt_status
```
- **connected** = MQTT verbunden (Echtzeit-Events aktiv)
- **disconnected** = MQTT getrennt

## Schritt 4: Beispiel-Automation

Erstellen Sie eine Automation zum Türöffnen:

```yaml
automation:
  - alias: "Tür öffnen Button"
    description: "Öffne Haustür bei Button-Druck"
    trigger:
      - platform: state
        entity_id: input_button.tuer_oeffnen
        to: "on"
    action:
      - service: lock.unlock
        target:
          entity_id: lock.siedle_haupteingang

  - alias: "Licht bei Bewegung"
    description: "Schalte Türlicht bei Bewegung ein"
    trigger:
      - platform: state
        entity_id: binary_sensor.eingang_bewegung
        to: "on"
    action:
      - service: switch.turn_on
        target:
          entity_id: switch.siedle_haupteingang_light
      - delay: "00:05:00"
      - service: switch.turn_off
        target:
          entity_id: switch.siedle_haupteingang_light

  - alias: "Klingel-Benachrichtigung"
    description: "Benachrichtigung bei Klingel (via MQTT)"
    trigger:
      - platform: event
        event_type: siedle_event
    action:
      - service: notify.mobile_app_iphone
        data:
          title: "🔔 Klingel"
          message: "Jemand steht vor der Tür!"
```

## Services

### siedle.open_door
```yaml
service: siedle.open_door
data:
  contact_id: "optional"  # Leer = erste Tür
```

### siedle.toggle_light
```yaml
service: siedle.toggle_light
data:
  contact_id: "optional"  # Leer = erste Tür
```

## Optionen

Nach der Einrichtung können Sie Optionen ändern:

1. Gehen Sie zu **Einstellungen** → **Geräte & Dienste**
2. Klicken Sie auf **Siedle** → **Konfigurieren**

**Verfügbare Optionen:**
- ✅ **MQTT aktivieren** - Echtzeit-Events (Standard: An)

## Fehlersuche

### Debug-Logging aktivieren

Fügen Sie zu `configuration.yaml` hinzu:

```yaml
logger:
  default: info
  logs:
    custom_components.siedle: debug
    siedle_api: debug
```

### MQTT prüfen

Prüfen Sie den Sensor:
```yaml
sensor.siedle_mqtt_status
```

Sollte "connected" anzeigen.

### QR-Code Fehler

- Stellen Sie sicher, dass Sie die **kompletten JSON-Daten** kopieren
- Format muss sein: `{"susUrl":"...", "setupKey":"..."}`
- Testen Sie den QR-Scanner vorher: http://www.stefan-altheimer.de/siedle/index.html

## Deinstallation

1. Entfernen Sie die Integration über die UI
2. Löschen Sie `custom_components/siedle/`
3. Starten Sie Home Assistant neu

## Support

Bei Problemen:
1. Aktivieren Sie Debug-Logging
2. Prüfen Sie die Logs unter **Einstellungen** → **System** → **Logs**
3. Öffnen Sie ein Issue auf GitHub

---

**Viel Erfolg mit Ihrer Siedle Integration! 🏠🔐**
