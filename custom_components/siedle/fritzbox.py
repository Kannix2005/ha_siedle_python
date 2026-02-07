"""Fritz!Box TR-064 Click-to-Dial integration for Siedle (F13).

Uses TR-064 SOAP protocol to initiate calls from a Fritz!Box phone
when the doorbell rings. This allows using a DECT phone as doorbell
notification device.

Docs: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/x_voip-avm.pdf
"""
import logging
import hashlib
import asyncio
from xml.etree import ElementTree

import aiohttp

_LOGGER = logging.getLogger(__name__)

# TR-064 endpoints
TR064_CONTROL_URL = "/upnp/control/x_voip"
TR064_SERVICE_TYPE = "urn:dslforum-org:service:X_VoIP:1"

# Dial action
ACTION_DIAL_NUMBER = "X_AVM-DE_DialNumber"
ACTION_DIAL_HANGUP = "X_AVM-DE_DialHangup"
ACTION_GET_PHONE_PORT = "X_AVM-DE_GetPhonePort"


class FritzBoxDialer:
    """Fritz!Box TR-064 dialer for Click-to-Dial."""

    def __init__(
        self,
        host: str = "fritz.box",
        username: str = "admin",
        password: str = "",
        phone_number: str = "",
    ):
        """Initialize dialer.
        
        Args:
            host: Fritz!Box hostname or IP
            username: Fritz!Box admin user
            password: Fritz!Box password
            phone_number: Number to dial (e.g. **9 for all phones, **610 for DECT phone 1)
        """
        self._host = host
        self._username = username
        self._password = password
        self._phone_number = phone_number
        self._base_url = f"http://{host}:49000"
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            auth = aiohttp.BasicAuth(self._username, self._password)
            self._session = aiohttp.ClientSession(auth=auth)
        return self._session

    def _build_soap_body(self, action: str, arguments: dict | None = None) -> str:
        """Build TR-064 SOAP XML request body."""
        args_xml = ""
        if arguments:
            for key, value in arguments.items():
                args_xml += f"<{key}>{value}</{key}>"

        return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{TR064_SERVICE_TYPE}">
      {args_xml}
    </u:{action}>
  </s:Body>
</s:Envelope>"""

    async def _soap_request(self, action: str, arguments: dict | None = None) -> str | None:
        """Send TR-064 SOAP request.
        
        Returns:
            Response XML body or None on error.
        """
        session = await self._get_session()
        url = f"{self._base_url}{TR064_CONTROL_URL}"
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{TR064_SERVICE_TYPE}#{action}"',
        }
        body = self._build_soap_body(action, arguments)

        try:
            async with session.post(url, headers=headers, data=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                response_text = await resp.text()
                if resp.status == 200:
                    _LOGGER.debug("TR-064 %s OK: %s", action, response_text[:200])
                    return response_text
                elif resp.status == 401:
                    _LOGGER.error("TR-064 authentication failed — check Fritz!Box credentials")
                    return None
                else:
                    _LOGGER.error("TR-064 %s failed: HTTP %s — %s", action, resp.status, response_text[:200])
                    return None
        except aiohttp.ClientError as e:
            _LOGGER.error("TR-064 connection error to %s: %s", self._host, e)
            return None
        except asyncio.TimeoutError:
            _LOGGER.error("TR-064 timeout connecting to %s", self._host)
            return None

    async def dial(self, number: str | None = None) -> bool:
        """Initiate a call on Fritz!Box.
        
        Args:
            number: Phone number to dial. Uses configured number if None.
                    Special numbers:
                    - **9: Ring all phones
                    - **610: DECT phone 1
                    - **611: DECT phone 2
                    - etc.
        
        Returns:
            True if dial request was accepted.
        """
        target = number or self._phone_number
        if not target:
            _LOGGER.error("No phone number configured for Fritz!Box dial")
            return False

        _LOGGER.info("Fritz!Box: Dialing %s on %s", target, self._host)
        result = await self._soap_request(
            ACTION_DIAL_NUMBER,
            {"NewX_AVM-DE_PhoneNumber": target},
        )
        return result is not None

    async def hangup(self) -> bool:
        """Hang up current Fritz!Box call.
        
        Returns:
            True if hangup was successful.
        """
        _LOGGER.info("Fritz!Box: Hanging up on %s", self._host)
        result = await self._soap_request(ACTION_DIAL_HANGUP)
        return result is not None

    async def dial_and_hangup(self, ring_duration: int = 30, number: str | None = None) -> bool:
        """Ring a phone for a specified duration, then hang up.
        
        This is the typical doorbell use case: ring the DECT phone(s) for
        a few seconds, then automatically hang up.
        
        Args:
            ring_duration: How long to ring in seconds (default 30).
            number: Number to dial (uses configured if None).
        
        Returns:
            True if successful.
        """
        success = await self.dial(number)
        if success:
            await asyncio.sleep(ring_duration)
            await self.hangup()
        return success

    async def test_connection(self) -> bool:
        """Test Fritz!Box TR-064 connectivity.
        
        Returns:
            True if connection and authentication work.
        """
        try:
            result = await self._soap_request(ACTION_GET_PHONE_PORT, {"NewIndex": "1"})
            if result:
                _LOGGER.info("Fritz!Box TR-064 connection test successful")
                return True
            return False
        except Exception as e:
            _LOGGER.error("Fritz!Box connection test failed: %s", e)
            return False

    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
