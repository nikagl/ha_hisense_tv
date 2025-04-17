"""Hisene TV integration helper methods."""
import asyncio
import json
import logging
import time
import re
import uuid
import hashlib
import random
import os
import ssl

from homeassistant.components import mqtt
from homeassistant.const import MAJOR_VERSION, MINOR_VERSION
from homeassistant.helpers.storage import STORAGE_DIR

from .const import DEFAULT_CLIENT_ID, DOMAIN, CERT_FILE, KEY_FILE

_LOGGER = logging.getLogger(__name__)


class TokenError(Exception):
    """Exception raised when there's an error with token operations."""
    pass


class HisenseTvMqttManager:
    """Centralized MQTT client manager for Hisense TV components."""

    def __init__(self, hass, config_entry):
        """Initialize the MQTT manager."""
        self.hass = hass
        self.config_entry = config_entry
        self.data = dict(config_entry.data)
        self._client_id = self.data.get("client_id")
        self._username = self.data.get("username")
        self._password = self.data.get("password")  # This is the access token
        self._refresh_token = self.data.get("refresh_token")
        self._mqtt_in = self.data.get("mqtt_in")
        self._mqtt_out = self.data.get("mqtt_out")
        self._subscriptions = {}

    def _in_topic(self, pattern):
        """Format incoming topic pattern."""
        if self._mqtt_in is None:
            return pattern.replace("%s", "")
        return pattern.replace("%s", self._mqtt_in)

    def _out_topic(self, pattern):
        """Format outgoing topic pattern."""
        # If we have a client_id, use that for more specific topic
        if self._client_id:
            return pattern.replace("%s", self._client_id)
        
        if self._mqtt_out is None:
            return pattern.replace("%s", "")
        return pattern.replace("%s", self._mqtt_out)

    async def check_token_validity(self):
        """Check if token is valid and refresh if needed."""
        from .config_flow import HisenseTvFlow
        
        try:
            # Check token and refresh if needed
            token_valid = await HisenseTvFlow.async_check_token_validity(self.hass, self.config_entry)
            
            if token_valid:
                # Update local token data with possibly refreshed values
                self.data = dict(self.config_entry.data)
                self._password = self.data.get("password")  # Updated access token
                self._refresh_token = self.data.get("refresh_token")
                return True
            return False
        except Exception as ex:
            _LOGGER.error(f"Error checking token validity: {ex}")
            return False

    async def subscribe(self, topic, callback):
        """Subscribe to MQTT topic with certificate support."""
        # Get the certificate paths
        storage_dir = self.hass.config.path(STORAGE_DIR, DOMAIN)
        cert_file = os.path.join(storage_dir, CERT_FILE)
        key_file = os.path.join(storage_dir, KEY_FILE)

        # Format the topic
        formatted_topic = self._in_topic(topic)
        
        # Add detailed logging
        _LOGGER.debug("Subscribing to MQTT topic: %s", formatted_topic)
        
        # Subscribe with enhanced options
        try:
            unsubscribe = await mqtt.async_subscribe(
                hass=self.hass,
                topic=formatted_topic,
                msg_callback=callback,
                # The HA MQTT component will use the certificates if they're available
            )
            _LOGGER.debug("MQTT subscription completed successfully")
            return unsubscribe
        except Exception as ex:
            _LOGGER.error(f"Error subscribing to {formatted_topic}: {ex}")
            return None

    async def publish(self, topic, payload, retain=False):
        """Publish to MQTT topic with certificate support after checking token validity."""
        # Always check token validity before sending commands
        await self.check_token_validity()
        
        # Format the topic
        formatted_topic = self._out_topic(topic)
        
        # Add detailed logging
        _LOGGER.debug("Publishing to MQTT topic: %s with payload: %s", formatted_topic, payload)
        
        try:
            # Use our dedicated Paho MQTT client for Hisense TV
            from .mqtt_client import HisensePahoMqttClient
            
            # Create a Paho MQTT client with our credentials
            client = HisensePahoMqttClient(
                hass=self.hass,
                client_id=self._client_id,
                username=self._username,
                password=self._password
            )
            
            # Send the command using Paho MQTT with certificates
            result = await client.publish(formatted_topic, payload, retain)
            
            if result:
                _LOGGER.debug("MQTT publish completed successfully")
            else:
                _LOGGER.warning("MQTT publish completed with errors")
                
            return result
        except Exception as ex:
            _LOGGER.error(f"Error publishing to {formatted_topic}: {ex}")
            return False
    
    async def unsubscribe_all(self):
        """Unsubscribe from all topics."""
        for unsubscribe in list(self._subscriptions.values()):
            unsubscribe()
        self._subscriptions = {}

async def mqtt_pub_sub(hass, pub, sub, payload=""):
    """Wrapper for publishing MQTT topics and receive replies on a subscibed topic."""
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()

    def put(*args):
        loop.call_soon_threadsafe(queue.put_nowait, args)

    async def get():
        while True:
            yield await asyncio.wait_for(queue.get(), timeout=10)

    unsubscribe = await mqtt.async_subscribe(hass=hass, topic=sub, msg_callback=put)
    await mqtt.async_publish(hass=hass, topic=pub, payload=payload)
    return get(), unsubscribe


def generate_token(mac=None, timestamp=None):
    """Generate authentication token using the same method as hisense.py."""
    import time
    import hashlib
    import re
    import random
    
    # Use current timestamp if none provided
    if timestamp is None:
        timestamp = int(time.time())
    
    # Generate a random MAC address if none provided
    if mac is None or not mac:
        # Generate random MAC address
        mac_bytes = [random.randint(0x00, 0xFF) for _ in range(6)]
        mac = ':'.join(f'{octet:02x}' for octet in mac_bytes)
    
    _LOGGER.debug(f"Using MAC Address: {mac}")
    _LOGGER.debug(f"Using timestamp: {timestamp}")

    # Calculate hashes exactly as in hisense.py
    def string_to_hash(input_str):
        return hashlib.md5(input_str.encode("utf-8")).hexdigest().upper()
    
    def cross_sum(n):
        return sum(int(digit) for digit in str(n))

    first_hash = string_to_hash("&vidaa#^app")
    _LOGGER.debug(f"First Hash: {first_hash}")
    
    # This matches the hard-coded hash from hisense.py
    second_hash = string_to_hash(f"38D65DC30F45109A369A86FCE866A85B${mac}")
    _LOGGER.debug(f"Second Hash: {second_hash}")
    
    last_digit_of_cross_sum = cross_sum(timestamp) % 10
    _LOGGER.debug(f"Last digit of cross sum: {last_digit_of_cross_sum}")
    
    third_hash = string_to_hash(f"his{last_digit_of_cross_sum}h*i&s%e!r^v0i1c9")
    _LOGGER.debug(f"Third Hash: {third_hash}")
    
    fourth_hash = string_to_hash(f"{timestamp}${third_hash[:6]}")
    _LOGGER.debug(f"Fourth Hash: {fourth_hash}")

    username = f"his${timestamp}"
    password = fourth_hash
    client_id = f"{mac}$his${second_hash[:6]}_vidaacommon_001"
    
    _LOGGER.debug(f"Generated username: {username}")
    _LOGGER.debug(f"Generated client_id: {client_id}")
    
    return {
        "username": username,
        "password": password,
        "client_id": client_id,
        "timestamp": timestamp,
        "mac": mac
    }


class HisenseTvBase:
    """Base class for Hisense TV entities."""

    def __init__(
        self,
        hass,
        name,
        mqtt_in,
        mqtt_out,
        mac,
        uid,
        ip_address,
        username=None,
        password=None,
        client_id=None,
        refresh_token=None,
        config_entry=None,
        mqtt_manager=None,
    ):
        """Initialize the base class."""
        self._hass = hass
        self._name = name
        self._mqtt_in = mqtt_in
        self._mqtt_out = mqtt_out
        self._mac = mac
        self._unique_id = uid
        self._ip_address = ip_address
        self._icon = "mdi:television"
        self._subscriptions = {}
        
        # Properly store authentication properties
        self._username = username
        self._password = password  # This is the access token
        self._client_id = client_id
        self._refresh_token = refresh_token
        self._config_entry = config_entry
        
        # Use provided MQTT manager or create new one
        self._mqtt_manager = mqtt_manager or (
            HisenseTvMqttManager(hass, config_entry) if config_entry else None
        )
        
        # For logging purposes
        if client_id and username and password:
            _LOGGER = logging.getLogger(__name__)
            _LOGGER.debug(f"Initialized with client_id: {client_id}")
            _LOGGER.debug(f"Using username: {username}")
            # Don't log the actual password/token for security
            _LOGGER.debug(f"Token present: {bool(password)}")
        
    async def check_token_validity(self):
        """Check if token is valid and refresh if needed."""
        if self._mqtt_manager:
            return await self._mqtt_manager.check_token_validity()
        
        if self._config_entry is None:
            return False
            
        from .config_flow import HisenseTvFlow
        
        # This follows the same logic as check_and_refresh_token in hisense.py
        try:
            # Check token and refresh if needed
            token_valid = await HisenseTvFlow.async_check_token_validity(self._hass, self._config_entry)
            
            if token_valid:
                # Update local token data with possibly refreshed values
                data = dict(self._config_entry.data)
                self._password = data.get("password")  # Updated access token
                self._refresh_token = data.get("refresh_token")
                return True
            return False
        except Exception as ex:
            _LOGGER.error(f"Error checking token validity: {ex}")
            return False

    def _in_topic(self, pattern):
        """Format incoming topic pattern."""
        if self._mqtt_manager:
            return self._mqtt_manager._in_topic(pattern)
            
        if self._mqtt_in is None:
            return pattern.replace("%s", "")
        return pattern.replace("%s", self._mqtt_in)

    def _out_topic(self, pattern):
        """Format outgoing topic pattern."""
        if self._mqtt_manager:
            return self._mqtt_manager._out_topic(pattern)
            
        # Check and refresh token before sending commands
        if self._client_id:
            # If we have a client_id, use that for more specific topic
            return pattern.replace("%s", self._client_id)
        
        if self._mqtt_out is None:
            return pattern.replace("%s", "")
        return pattern.replace("%s", self._mqtt_out)
        
    async def send_command(self, topic, payload):
        """Send command with token validity check."""
        if self._mqtt_manager:
            return await self._mqtt_manager.publish(topic, payload)
        
        # Always check token validity before sending commands
        if self._config_entry:
            await self.check_token_validity()
        
        # Use the updated token for commands
        return await mqtt.async_publish(
            hass=self._hass,
            topic=topic,
            payload=payload,
            retain=False,
        )