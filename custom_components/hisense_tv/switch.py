"""Hisense TV switch entity"""
import logging

import wakeonlan

from homeassistant.components import mqtt
from homeassistant.components.switch import SwitchEntity
from homeassistant.components.switch import SwitchDeviceClass
from homeassistant.const import CONF_IP_ADDRESS, CONF_MAC, CONF_NAME

from .const import (
    CONF_MQTT_IN, 
    CONF_MQTT_OUT, 
    DEFAULT_NAME, 
    DOMAIN,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_CLIENT_ID,
    CONF_REFRESH_TOKEN
)
from .helper import HisenseTvBase, HisenseTvMqttManager

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up Hisense TV switch from config entry."""
    _LOGGER.debug("async_setup_entry config: %s", config_entry.data)
    
    # Get data from config entry
    data = dict(config_entry.data)
    
    # Get the MAC address - don't try to use alternatives if not present
    mac = data.get(CONF_MAC)
    
    # Get the centralized MQTT manager 
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
    
    # Create power on/off switch entity with the MQTT manager
    switch_entity = HisenseTvSwitch(
        hass=hass,
        name=data.get(CONF_NAME),
        mqtt_in=data.get(CONF_MQTT_IN),
        mqtt_out=data.get(CONF_MQTT_OUT),
        mac=mac,  # Use the MAC address as is, might be None
        uid=data.get("uid"),
        ip_address=data.get(CONF_IP_ADDRESS),
        username=data.get("username"),
        password=data.get("password"),
        client_id=data.get("client_id"),
        refresh_token=data.get("refresh_token"),
        config_entry=config_entry,
        mqtt_manager=mqtt_manager,
    )
    
    async_add_entities([switch_entity], True)


class HisenseTvSwitch(SwitchEntity, HisenseTvBase):
    """Representation of Hisense TV power switch."""
    
    def __init__(self, hass, name, mqtt_in, mqtt_out, mac, uid, ip_address,
                 username=None, password=None, client_id=None, 
                 refresh_token=None, config_entry=None, mqtt_manager=None):
        """Initialize the switch."""
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
        # Initialize switch state
        self._is_on = False
        self._attr_is_on = False  # For compatibility with newer HA versions
        
    @property
    def device_class(self):
        """Return the class of this device."""
        _LOGGER.debug("device_class")
        return SwitchDeviceClass.SWITCH
    
    @property
    def is_on(self):
        """Return True if entity is on."""
        return self._is_on
    
    async def async_turn_on(self, **kwargs):
        """Turn the device on."""
        # Use the power_cycle_tv method which properly handles TV state
        if self._mqtt_manager:
            topic = "/remoteapp/tv/remote_service/%s/actions/sendkey"
            await self._mqtt_manager.publish(
                topic,
                "KEY_POWER"
            )
        else:
            # Fallback to direct MQTT publish
            topic = self._out_topic("/remoteapp/tv/remote_service/%s/actions/sendkey")
            await mqtt.async_publish(
                hass=self.hass,
                topic=topic,
                payload="KEY_POWER",
                retain=False,
            )
        
        self._is_on = True
        self._attr_is_on = True
        self.async_write_ha_state()
    
    async def async_turn_off(self, **kwargs):
        """Turn the device off."""
        # Use power_cycle_tv method for both on and off to ensure consistent behavior
        if self._mqtt_manager:
            topic = "/remoteapp/tv/remote_service/%s/actions/sendkey"
            await self._mqtt_manager.publish(
                topic,
                "KEY_POWER"
            )
        else:
            # Fallback to direct MQTT publish
            topic = self._out_topic("/remoteapp/tv/remote_service/%s/actions/sendkey")
            await mqtt.async_publish(
                hass=self.hass,
                topic=topic,
                payload="KEY_POWER",
                retain=False,
            )
            
        self._is_on = False
        self._attr_is_on = False
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self):
        for unsubscribe in list(self._subscriptions.values()):
            unsubscribe()

    async def async_added_to_hass(self):
        """Subscribe to MQTT events using the centralized manager."""
        if self._mqtt_manager:
            # Use the MQTT manager for all subscriptions
            topic = "/remoteapp/mobile/broadcast/platform_service/actions/tvsleep"
            self._subscriptions["tvsleep"] = await self._mqtt_manager.subscribe(
                topic,
                self._message_received_turnoff
            )
            
            topic = "/remoteapp/mobile/broadcast/ui_service/state"
            self._subscriptions["state"] = await self._mqtt_manager.subscribe(
                topic,
                self._message_received_state
            )
            
            topic = "/remoteapp/mobile/broadcast/platform_service/actions/volumechange"
            self._subscriptions["volume"] = await self._mqtt_manager.subscribe(
                topic,
                self._message_received_state
            )
            
            topic = f"/remoteapp/mobile/%s/ui_service/data/sourcelist"
            self._subscriptions["sourcelist"] = await self._mqtt_manager.subscribe(
                topic,
                self._message_received_state
            )
        else:
            # Fallback to direct MQTT subscriptions
            topic = self._in_topic("/remoteapp/mobile/broadcast/platform_service/actions/tvsleep")
            self._subscriptions["tvsleep"] = await mqtt.async_subscribe(
                self._hass,
                topic,
                self._message_received_turnoff,
            )

            topic = self._in_topic("/remoteapp/mobile/broadcast/ui_service/state")
            self._subscriptions["state"] = await mqtt.async_subscribe(
                self._hass,
                topic,
                self._message_received_state,
            )

            topic = self._in_topic("/remoteapp/mobile/broadcast/platform_service/actions/volumechange")
            self._subscriptions["volume"] = await mqtt.async_subscribe(
                self._hass,
                topic,
                self._message_received_state,
            )

            topic = self._out_topic("/remoteapp/mobile/%s/ui_service/data/sourcelist")
            self._subscriptions["sourcelist"] = await mqtt.async_subscribe(
                self._hass,
                topic,
                self._message_received_state,
            )

    async def _message_received_turnoff(self, msg):
        """Handle the TV sleep/power off message"""
        _LOGGER.debug("message_received_turnoff, topic: %s", msg.topic)
        try:
            payload = msg.payload.decode('utf-8') if hasattr(msg.payload, 'decode') else str(msg.payload)
            _LOGGER.debug("Turnoff message payload: %s", payload)
        except Exception as e:
            _LOGGER.debug("Error decoding payload: %s", str(e))
        
        _LOGGER.debug("Setting TV state to OFF")
        self._is_on = False
        self.async_write_ha_state()

    async def _message_received_state(self, msg):
        """Handle the TV state message"""
        _LOGGER.debug("message_received_state, topic: %s", msg.topic)
        
        if msg.retain:
            _LOGGER.debug("SWITCH message_received_state - skip retained message")
            return

        try:
            payload = msg.payload.decode('utf-8') if hasattr(msg.payload, 'decode') else str(msg.payload)
            _LOGGER.debug("State message payload: %s", payload)
        except Exception as e:
            _LOGGER.debug("Error decoding payload: %s", str(e))
        
        _LOGGER.debug("Setting TV state to ON")
        self._is_on = True
        self.async_write_ha_state()

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._unique_id)},
            "name": self._name,
            "manufacturer": DEFAULT_NAME,
        }

    @property
    def unique_id(self):
        """Return the unique id of the device."""
        return self._unique_id

    @property
    def name(self):
        return self._name

    @property
    def icon(self):
        return self._icon

    @property
    def should_poll(self):
        """No polling needed."""
        return False
