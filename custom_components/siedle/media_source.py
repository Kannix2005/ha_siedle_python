"""Media Source for Siedle integration — browse and play doorbell recordings."""
from __future__ import annotations

import logging
import os
from datetime import datetime

from homeassistant.components.media_player import MediaClass, MediaType
from homeassistant.components.media_source import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
    Unresolvable,
)
from homeassistant.core import HomeAssistant

from .const import DOMAIN, CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH

_LOGGER = logging.getLogger(__name__)

MIME_TYPE_WAV = "audio/wav"


async def async_get_media_source(hass: HomeAssistant) -> SiedleMediaSource:
    """Set up Siedle media source."""
    return SiedleMediaSource(hass)


class SiedleMediaSource(MediaSource):
    """Provide Siedle recordings as media source."""

    name = "Siedle Aufnahmen"

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize media source."""
        super().__init__(DOMAIN)
        self.hass = hass

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        """Resolve media to a playable URL."""
        # item.identifier format: "entry_id/filename"
        parts = item.identifier.split("/", 1)
        if len(parts) != 2:
            raise Unresolvable(f"Ungültiger Pfad: {item.identifier}")
        
        entry_id, filename = parts
        
        # Get recording path from config
        recording_path = self._get_recording_path(entry_id)
        if not recording_path:
            raise Unresolvable("Aufnahme-Pfad nicht konfiguriert")
        
        # Full filesystem path
        full_path = os.path.join(
            self.hass.config.path(recording_path, "doorbell"),
            filename
        )
        
        if not await self.hass.async_add_executor_job(os.path.exists, full_path):
            raise Unresolvable(f"Datei nicht gefunden: {filename}")
        
        # Convert to URL — files in www/ are served at /local/
        if recording_path.startswith("www/"):
            relative = f"{recording_path[4:]}/doorbell/{filename}"
            url = f"/local/{relative}"
        else:
            raise Unresolvable("Aufnahmen müssen im www/ Ordner liegen")
        
        return PlayMedia(url=url, mime_type=MIME_TYPE_WAV)

    async def async_browse_media(
        self,
        item: MediaSourceItem,
    ) -> BrowseMediaSource:
        """Browse available recordings."""
        if item.identifier:
            # Browsing a specific entry's recordings
            return await self._async_browse_entry(item.identifier)
        
        # Root level — list config entries
        children = []
        for entry_id, data in self.hass.data.get(DOMAIN, {}).items():
            if not isinstance(data, dict):
                continue
            
            endpoint_id = ""
            for entry in self.hass.config_entries.async_entries(DOMAIN):
                if entry.entry_id == entry_id:
                    endpoint_id = entry.data.get("endpoint_id", "")[:8]
                    break
            
            children.append(
                BrowseMediaSource(
                    domain=DOMAIN,
                    identifier=entry_id,
                    media_class=MediaClass.DIRECTORY,
                    media_content_type=MediaType.MUSIC,
                    title=f"Siedle {endpoint_id}",
                    can_play=False,
                    can_expand=True,
                    thumbnail=None,
                )
            )
        
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier="",
            media_class=MediaClass.DIRECTORY,
            media_content_type=MediaType.MUSIC,
            title="Siedle Aufnahmen",
            can_play=False,
            can_expand=True,
            children=children,
        )

    async def _async_browse_entry(self, identifier: str) -> BrowseMediaSource:
        """Browse recordings for a specific config entry."""
        # identifier could be just entry_id (listing files) or entry_id/filename  
        parts = identifier.split("/", 1)
        entry_id = parts[0]
        
        recording_path = self._get_recording_path(entry_id)
        if not recording_path:
            return BrowseMediaSource(
                domain=DOMAIN,
                identifier=entry_id,
                media_class=MediaClass.DIRECTORY,
                media_content_type=MediaType.MUSIC,
                title="Keine Aufnahmen",
                can_play=False,
                can_expand=False,
                children=[],
            )
        
        recordings_dir = self.hass.config.path(recording_path, "doorbell")
        
        # List WAV files
        files = await self.hass.async_add_executor_job(
            self._list_recordings, recordings_dir
        )
        
        children = []
        for filename, size, mtime in files:
            # Parse timestamp from filename: doorbell_YYYYMMDD_HHMMSS.wav
            timestamp_str = ""
            try:
                name_parts = filename.replace(".wav", "").split("_")
                if len(name_parts) >= 3:
                    date_str = name_parts[-2]  # YYYYMMDD
                    time_str = name_parts[-1]  # HHMMSS
                    dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                    timestamp_str = dt.strftime("%d.%m.%Y %H:%M:%S")
            except (ValueError, IndexError):
                timestamp_str = datetime.fromtimestamp(mtime).strftime("%d.%m.%Y %H:%M:%S")
            
            title = f"🔔 {timestamp_str} ({size / 1024:.0f} KB)"
            
            children.append(
                BrowseMediaSource(
                    domain=DOMAIN,
                    identifier=f"{entry_id}/{filename}",
                    media_class=MediaClass.MUSIC,
                    media_content_type=MediaType.MUSIC,
                    title=title,
                    can_play=True,
                    can_expand=False,
                    thumbnail=None,
                )
            )
        
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=entry_id,
            media_class=MediaClass.DIRECTORY,
            media_content_type=MediaType.MUSIC,
            title=f"Siedle Aufnahmen ({len(files)} Dateien)",
            can_play=False,
            can_expand=True,
            children=children,
        )

    def _list_recordings(self, directory: str) -> list[tuple[str, int, float]]:
        """List WAV files in directory, sorted by modification time (newest first)."""
        if not os.path.isdir(directory):
            return []
        
        files = []
        try:
            for f in os.listdir(directory):
                if f.lower().endswith(".wav"):
                    full_path = os.path.join(directory, f)
                    stat = os.stat(full_path)
                    files.append((f, stat.st_size, stat.st_mtime))
        except OSError as e:
            _LOGGER.error(f"Fehler beim Lesen des Aufnahme-Verzeichnisses: {e}")
            return []
        
        # Sort by modification time, newest first
        files.sort(key=lambda x: x[2], reverse=True)
        return files

    def _get_recording_path(self, entry_id: str) -> str | None:
        """Get recording path from config entry options."""
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            if entry.entry_id == entry_id:
                return entry.options.get(CONF_RECORDING_PATH, DEFAULT_RECORDING_PATH)
        return None
