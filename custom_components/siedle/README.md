# Siedle Door Intercom Integration for Home Assistant

Custom integration for Siedle SUS (Siedle Unterwegs) door intercom systems.

## Features

- 🔐 **Lock Entity** - Control doors (unlock = open door)
- 💡 **Switch Entity** - Toggle door lights
- 📊 **Sensor Entity** - MQTT connection status
- 📡 **MQTT Events** - Real-time notifications
- 🔑 **Services** - `siedle.open_door`, `siedle.toggle_light`
- 🌐 **QR Code Setup** - Easy configuration via QR code

## Installation

### Manual Installation

1. Copy the `custom_components/siedle` folder to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant
3. Go to Settings → Devices & Services → Add Integration
4. Search for "Siedle"

### HACS (Recommended)

1. Add this repository to HACS as a custom repository
2. Install "Siedle Door Intercom" from HACS
3. Restart Home Assistant
4. Add integration via UI

## Setup

1. Open the Siedle mobile app
2. Go to Settings → Multi-Device Setup
3. In Home Assistant: Add Integration → Siedle
4. Click the QR scanner link: http://www.stefan-altheimer.de/siedle/index.html
5. Scan the QR code from the Siedle app
6. Copy the JSON data and paste it into Home Assistant

## Entities

### Lock
- `lock.siedle_[door_name]` - Unlock opens the door

### Switch
- `switch.siedle_[door_name]_light` - Toggle door light

### Sensor
- `sensor.siedle_mqtt_status` - MQTT connection status

## Services

### `siedle.open_door`
Open/unlock a door.

```yaml
service: siedle.open_door
data:
  contact_id: "optional-contact-id"  # If omitted, uses first door
```

### `siedle.toggle_light`
Toggle door light.

```yaml
service: siedle.toggle_light
data:
  contact_id: "optional-contact-id"  # If omitted, uses first door
```

## Events

MQTT events are fired as `siedle_event`:

```yaml
automation:
  - alias: "Doorbell Ring"
    trigger:
      - platform: event
        event_type: siedle_event
    action:
      - service: notify.mobile_app
        data:
          message: "Someone is at the door!"
```

## Example Automation

```yaml
# Auto-open door on button press
automation:
  - alias: "Open Front Door"
    trigger:
      - platform: state
        entity_id: input_button.open_door
        to: "on"
    action:
      - service: lock.unlock
        target:
          entity_id: lock.siedle_haupteingang

# Turn on light at sunset
  - alias: "Door Light at Sunset"
    trigger:
      - platform: sun
        event: sunset
    action:
      - service: switch.turn_on
        target:
          entity_id: switch.siedle_haupteingang_light
```

## Configuration

After setup, you can configure options:

- **Enable MQTT** - Enable/disable MQTT real-time events (default: enabled)

## Troubleshooting

### Enable Debug Logging

Add to `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.siedle: debug
```

### Check MQTT Connection

Check the sensor `sensor.siedle_mqtt_status` - should show "connected".

### Invalid QR Code

Make sure to copy the complete JSON data including `{` and `}`.

## Credits

Based on reverse engineering of the Siedle SUS Android app.

## License

MIT License
