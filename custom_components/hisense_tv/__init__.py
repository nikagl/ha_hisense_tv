"""Support for Hisense TV."""
import datetime
import logging
import os
from homeassistant.helpers.storage import Store
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PLATFORMS, VERSION, VERSION_STORAGE_KEY
from .helper import HisenseTvMqttManager

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass, config):
    """Set up the Hisense TV component."""
    # Create storage for version data
    store = Store(hass, 1, f"{DOMAIN}/{VERSION_STORAGE_KEY}")
    stored_data = await store.async_load() or {"version": VERSION}
    
    # Compare stored version with current version
    if stored_data.get("version") != VERSION:
        # Version has changed - this is a new install or update
        _LOGGER.info("Hisense TV integration updated to version %s", VERSION)
        
    # Save current version
    await store.async_save({"version": VERSION})
    
    # Make version available in hass.data
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    
    hass.data[DOMAIN]["version"] = VERSION
    
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Hisense TV from a config entry."""
    # Import here to avoid circular imports
    from .config_flow import HisenseTvFlow
    
    # Initialize domain data structure if needed
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
        
    # Make version available directly in the domain data
    hass.data[DOMAIN]["version"] = VERSION
    
    # Create a centralized MQTT manager for this entry
    mqtt_manager = HisenseTvMqttManager(hass, entry)
    
    # Store the MQTT manager in hass.data for access by all components
    # Use entry_id as key to support multiple TVs
    if "mqtt_managers" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["mqtt_managers"] = {}
    
    hass.data[DOMAIN]["mqtt_managers"][entry.entry_id] = mqtt_manager
    
    # Store entry data in hass.data for consistency
    hass.data[DOMAIN][entry.entry_id] = {
        "mqtt_manager": mqtt_manager,
        "mac": entry.data.get("mac"),
        "ip_address": entry.data.get("ip_address"),
    }
    
    # Set up token refresh job - check every hour similar to hisense.py approach
    async def refresh_tokens_periodically(now=None):
        """Check and refresh tokens periodically."""
        await HisenseTvFlow.async_check_token_validity(hass, entry)
    
    # Use the properly imported function
    async_track_time_interval(
        hass,
        refresh_tokens_periodically,
        datetime.timedelta(hours=1)
    )
    
    # Forward the entry setup to all platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    return True


async def async_unload_entry(hass, entry):
    """Unload a config entry."""
    # Clean up MQTT manager if it exists
    if (
        DOMAIN in hass.data
        and "mqtt_managers" in hass.data[DOMAIN]
        and entry.entry_id in hass.data[DOMAIN]["mqtt_managers"]
    ):
        mqtt_manager = hass.data[DOMAIN]["mqtt_managers"][entry.entry_id]
        await mqtt_manager.unsubscribe_all()
        del hass.data[DOMAIN]["mqtt_managers"][entry.entry_id]
    
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)