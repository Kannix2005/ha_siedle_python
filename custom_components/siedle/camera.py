"""Siedle camera platform stub (F3/F14).

Provides a camera entity for future Siedle video integration.
Currently supports:
  - Placeholder image when idle
  - Recording file as "snapshot" after a call
  
Future: MJPEG/HLS stream proxy if Siedle exposes a video endpoint.
"""
import logging
import os
from datetime import datetime

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Siedle camera platform."""
    # Only add camera if we have an API instance
    data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    if not data:
        return

    async_add_entities([SiedleDoorCamera(hass, entry)], True)


class SiedleDoorCamera(Camera):
    """Siedle door station camera entity.
    
    Shows the last snapshot or recording thumbnail from doorbell events.
    Future: live stream proxy.
    """

    _attr_has_entity_name = True
    _attr_name = "Türstation Kamera"
    _attr_supported_features = CameraEntityFeature(0)
    _attr_brand = "Siedle"
    _attr_model = "SUS2"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize camera."""
        super().__init__()
        self._hass = hass
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_camera"
        self._last_image: bytes | None = None
        self._last_image_time: datetime | None = None
        self._is_streaming = False

    @property
    def is_on(self) -> bool:
        """Return if camera is enabled."""
        return True

    @property
    def is_streaming(self) -> bool:
        """Return if the camera is streaming (not yet supported)."""
        return self._is_streaming

    @property
    def extra_state_attributes(self) -> dict:
        """Return extra state attributes."""
        attrs = {}
        if self._last_image_time:
            attrs["last_snapshot"] = self._last_image_time.isoformat()
        return attrs

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return last captured image."""
        return self._last_image

    def set_snapshot(self, image_data: bytes) -> None:
        """Update camera with new snapshot image (called from SIP manager)."""
        self._last_image = image_data
        self._last_image_time = datetime.now()
        self.schedule_update_ha_state()

    async def async_update(self) -> None:
        """Update camera state — currently a no-op (passive entity)."""
        pass
