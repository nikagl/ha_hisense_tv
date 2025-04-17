"""Hisense TV media player entity."""
import asyncio
import json
from json.decoder import JSONDecodeError
import logging

import voluptuous as vol
import wakeonlan

from homeassistant.components import mqtt
from homeassistant.components.media_player import (
    MediaPlayerDeviceClass,
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaType,
    MediaClass,
    PLATFORM_SCHEMA,
    BrowseMedia,
)
from homeassistant.config_entries import SOURCE_IMPORT
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_MAC,
    CONF_NAME,
    STATE_OFF,
    STATE_ON,
)
from homeassistant.helpers import config_validation as cv

from .const import (
    ATTR_CODE,
    CONF_MQTT_IN,
    CONF_MQTT_OUT,
    CONF_CLIENT_MAC,
    DEFAULT_NAME,
    DEFAULT_PORT,
    DOMAIN,
)
from .helper import (
    HisenseTvBase, 
    mqtt_pub_sub,
    generate_token,
    TokenError,
    HisenseTvMqttManager,
)

REQUIREMENTS = []

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_MAC): cv.string,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Optional(CONF_IP_ADDRESS): cv.string,
        vol.Required(CONF_MQTT_IN): cv.string,
        vol.Required(CONF_MQTT_OUT): cv.string,
    }
)

AUTHENTICATE_SCHEMA = {
    vol.Required(ATTR_CODE): cv.Number,
}


async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    """Set up the media player platform."""

    if discovery_info:
        # Now handled by zeroconf in the config flow
        _LOGGER.debug("async_setup_platform with discovery_info")
        return

    mac = config[CONF_MAC]
    for entry in hass.config_entries.async_entries(DOMAIN):
        _LOGGER.debug("entry: %s", entry.data)
        if entry.data[CONF_MAC] == mac:
            return

    entry_data = {
        CONF_NAME: config[CONF_NAME],
        CONF_MAC: config[CONF_MAC],
        CONF_IP_ADDRESS: config.get(CONF_IP_ADDRESS, wakeonlan.BROADCAST_IP),
        CONF_MQTT_IN: config[CONF_MQTT_IN],
        CONF_MQTT_OUT: config[CONF_MQTT_OUT],
    }

    hass.async_create_task(
        hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_IMPORT}, data=entry_data
        )
    )


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the Hisense TV media player from a config entry."""
    from .config_flow import HisenseTvFlow
    
    # Get data from config entry
    data = dict(config_entry.data)
    
    # Get MAC address - don't try to use alternatives
    mac = data.get(CONF_MAC)
    
    # Ensure IP address has a default if not provided
    ip_address = data.get(CONF_IP_ADDRESS, wakeonlan.BROADCAST_IP)
    
    # Get the centralized MQTT manager or create a new one if it doesn't exist yet
    mqtt_manager = None
    if (DOMAIN in hass.data and 
        "mqtt_managers" in hass.data[DOMAIN] and 
        config_entry.entry_id in hass.data[DOMAIN]["mqtt_managers"]):
        mqtt_manager = hass.data[DOMAIN]["mqtt_managers"][config_entry.entry_id]
    
    if mqtt_manager is None:
        # If there's no manager yet (which shouldn't happen), create a new one
        mqtt_manager = HisenseTvMqttManager(hass, config_entry)
        
        # Store it for future use
        if DOMAIN not in hass.data:
            hass.data[DOMAIN] = {}
        if "mqtt_managers" not in hass.data[DOMAIN]:
            hass.data[DOMAIN]["mqtt_managers"] = {}
        hass.data[DOMAIN]["mqtt_managers"][config_entry.entry_id] = mqtt_manager
    
    # Create media player entity with the MQTT manager
    entity = HisenseTvMediaPlayer(
        hass=hass,
        name=data.get(CONF_NAME),
        mqtt_in=data.get(CONF_MQTT_IN),
        mqtt_out=data.get(CONF_MQTT_OUT),
        mac=mac,  # Use MAC as is, might be None
        uid=data.get("uid"),
        ip_address=ip_address,
        port=data.get("port", DEFAULT_PORT),
        username=data.get("username"),
        password=data.get("password"),
        client_id=data.get("client_id"),
        refresh_token=data.get("refresh_token"),
        config_entry=config_entry,
        mqtt_manager=mqtt_manager,
    )
    
    # Store data in hass.data
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    
    hass.data[DOMAIN][config_entry.entry_id] = {
        "mac": mac,
        "ip_address": ip_address,
        "mqtt_manager": mqtt_manager,
    }
    
    async_add_entities([entity], True)


class HisenseTvMediaPlayer(MediaPlayerEntity, HisenseTvBase):
    """Hisense TV media player entity."""

    def __init__(self, hass, name, mqtt_in, mqtt_out, mac, uid, ip_address,
                 port=None, username=None, password=None, client_id=None, 
                 refresh_token=None, config_entry=None, mqtt_manager=None):
        """Initialize the entity."""
        HisenseTvBase.__init__(
            self=self,
            hass=hass,
            name=name,
            mqtt_in=mqtt_in,
            mqtt_out=mqtt_out,
            mac=mac,
            uid=uid,
            ip_address=ip_address,
            username=username,
            password=password,
            client_id=client_id,
            refresh_token=refresh_token,
            config_entry=config_entry,
            mqtt_manager=mqtt_manager,
        )
        self._port = port
        self._state = STATE_OFF
        self._muted = False
        self._volume = 0
        self._source_name = None
        self._source_id = None
        self._source_list = {"App": {}}
        self._title = None
        self._channel_name = None
        self._channel_num = None
        self._channel_infos = {}
        self._app_list = {}

    async def async_update(self):
        """Update TV state."""
        # Use the MQTT manager to check token validity
        if self._mqtt_manager:
            await self._mqtt_manager.check_token_validity()
        else:
            # Fallback to previous method
            from .config_flow import HisenseTvFlow
            await HisenseTvFlow.async_check_token_validity(self.hass, self._config_entry)
        
        # Get fresh data from config entry after possible token refresh
        data = dict(self._config_entry.data)
        self._password = data.get("password")  # Updated access token
        self._refresh_token = data.get("refresh_token")
        
        # Continue with regular update
        # ...existing code...

    async def async_added_to_hass(self):
        """Subscribe to MQTT events."""
        # Use MQTT manager for subscriptions if available
        if self._mqtt_manager:
            self._subscriptions["tvsleep"] = await self._mqtt_manager.subscribe(
                "/remoteapp/mobile/broadcast/platform_service/actions/tvsleep",
                self._message_received_turnoff
            )
            
            # Add other subscriptions using the same pattern
            # ...
        else:
            # Fallback to direct MQTT subscriptions
            self._subscriptions["tvsleep"] = await mqtt.async_subscribe(
                self._hass,
                self._in_topic(
                    "/remoteapp/mobile/broadcast/platform_service/actions/tvsleep"
                ),
                self._message_received_turnoff,
            )
            
            # Add other subscriptions
            # ...

    async def async_send_command(self, topic, payload):
        """Send command using MQTT manager."""
        if self._mqtt_manager:
            return await self._mqtt_manager.publish(topic, payload)
        else:
            # Fallback to direct MQTT publishing
            return await self.send_command(topic, payload)
            
    # ... rest of the class implementation ...
