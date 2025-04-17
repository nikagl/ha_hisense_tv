"""Hisense TV button entity"""
import logging

from homeassistant.components import mqtt
from homeassistant.components.button import ButtonEntity
from homeassistant.components.button import ButtonDeviceClass
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
    """Set up Hisense TV button from config entry."""
    _LOGGER.debug("button async_setup_entry config: %s", config_entry.data)
    
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
    
    # Create power button entity with the MQTT manager
    button_entity = HisenseTvPowerButton(
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
    
    async_add_entities([button_entity], True)


class HisenseTvPowerButton(ButtonEntity, HisenseTvBase):
    """Representation of Hisense TV power button."""
    
    def __init__(self, hass, name, mqtt_in, mqtt_out, mac, uid, ip_address,
                 username=None, password=None, client_id=None, 
                 refresh_token=None, config_entry=None, mqtt_manager=None):
        """Initialize the button."""
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
        self._attr_name = f"{name} Power"
        self._attr_unique_id = f"{self._unique_id}_power"
        
    @property
    def device_class(self):
        """Return the class of this device."""
        return ButtonDeviceClass.RESTART
    
    async def async_press(self):
        """Handle the button press."""
        # Send the power key press command
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
        
        self.async_write_ha_state()

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._unique_id)},
            "name": self._name,
            "manufacturer": DEFAULT_NAME,
        }

    @property
    def icon(self):
        return "mdi:power"

    @property
    def should_poll(self):
        """No polling needed."""
        return False
