"""Hisense TV MQTT client."""
import asyncio
import logging
import os
import ssl
import time
from homeassistant.helpers.storage import STORAGE_DIR

from .const import DOMAIN, CERT_FILE, KEY_FILE, VERSION

_LOGGER = logging.getLogger(__name__)

class HisensePahoMqttClient:
    """MQTT client using Paho MQTT with SSL certificates."""

    def __init__(self, hass, client_id, username, password):
        """Initialize the MQTT client."""
        self.hass = hass
        self.client_id = client_id
        self.username = username
        self.password = password
        
    async def publish(self, topic, payload, retain=False):
        """Publish a message to the MQTT broker using an executor to avoid blocking the event loop."""
        # Get the certificate paths
        storage_dir = self.hass.config.path(STORAGE_DIR, DOMAIN)
        cert_file = os.path.join(storage_dir, CERT_FILE)
        key_file = os.path.join(storage_dir, KEY_FILE)
        
        _LOGGER.debug(f"Publishing to topic {topic} with payload: {payload}")
        _LOGGER.debug(f"Using client_id: {self.client_id}")
        _LOGGER.debug(f"Using username: {self.username}")
        
        # Define the function that will run in the executor
        def mqtt_publish_in_thread():
            try:
                # Import inside the function to ensure it's only used in the thread
                import paho.mqtt.client as mqtt
                
                # Create a client
                client = mqtt.Client(client_id=self.client_id)
                
                # Set up connection result
                result = False
                publish_completed = asyncio.Event()
                
                # Set up connection callbacks
                def on_connect(client, userdata, flags, rc):
                    if rc == 0:
                        _LOGGER.debug("Connected to MQTT broker")
                        # Publish message after successful connection
                        client.publish(topic, payload, retain=retain)
                    else:
                        _LOGGER.error(f"Failed to connect to MQTT broker: {rc}")
                        publish_completed.set()
                
                def on_publish(client, userdata, mid):
                    _LOGGER.debug(f"Message {mid} published")
                    nonlocal result
                    result = True
                    publish_completed.set()
                
                def on_disconnect(client, userdata, rc):
                    _LOGGER.debug(f"Disconnected from MQTT broker: {rc}")
                    publish_completed.set()
                
                # Set up the callbacks
                client.on_connect = on_connect
                client.on_publish = on_publish
                client.on_disconnect = on_disconnect
                
                # Set up username/password if available
                if self.username and self.password:
                    client.username_pw_set(
                        self.username, 
                        self.password
                    )
                    _LOGGER.debug("Set username and password for MQTT client")
                
                # Configure SSL with certificates
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    _LOGGER.debug(f"Using certificates: {cert_file}, {key_file}")
                    # Create an SSL context - match the config_flow implementation
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    try:
                        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                        client.tls_set_context(ssl_context)
                        client.tls_insecure_set(True)
                        _LOGGER.debug("SSL configured successfully with context")
                    except ssl.SSLError as ssl_ex:
                        _LOGGER.error(f"SSL configuration error: {ssl_ex}")
                        return False
                else:
                    _LOGGER.warning(f"Certificate files not found, SSL not configured properly")
                
                # Connect to the broker
                try:
                    # Find the entry_id for this client_id by searching through the configured TVs
                    ip_address = None
                    port = 36669  # Default port if not specified
                    found_config = False
                    entry_id_used = None
                    
                    # Dump all entries in hass.data[DOMAIN] for debugging
                    _LOGGER.debug(f"MQTT Debug: Available entries in hass.data[{DOMAIN}]:")
                    for entry_id, entry_data in self.hass.data[DOMAIN].items():
                        if isinstance(entry_data, dict):
                            if 'ip_address' in entry_data:
                                _LOGGER.debug(f"MQTT Debug: Entry {entry_id}: IP={entry_data.get('ip_address')}, MAC={entry_data.get('mac', 'N/A')}")
                            elif 'mqtt_manager' in entry_data and hasattr(entry_data['mqtt_manager'], '_client_id'):
                                _LOGGER.debug(f"MQTT Debug: Entry {entry_id}: mqtt_manager client_id={entry_data['mqtt_manager']._client_id}")
                      # First search method: Look for MAC in client_id
                    _LOGGER.debug(f"MQTT Debug: Searching for TV with MAC in client_id: {self.client_id}")
                    for entry_id, entry_data in self.hass.data[DOMAIN].items():
                        if isinstance(entry_data, dict) and 'ip_address' in entry_data:
                            if 'mac' in entry_data and entry_data['mac'] and entry_data['mac'] in self.client_id:
                                ip_address = entry_data['ip_address']
                                if 'port' in entry_data:
                                    port = entry_data['port']
                                found_config = True
                                entry_id_used = entry_id
                                _LOGGER.debug(f"MQTT Debug: Found TV by MAC match in client_id: entry_id={entry_id}, ip_address={ip_address}, port={port}")
                                break
                    
                    # Second search method: Look for matching mqtt_manager client_id
                    if not found_config:
                        _LOGGER.debug(f"MQTT Debug: Searching for TV with mqtt_manager client_id: {self.client_id}")
                        for entry_id, entry_data in self.hass.data[DOMAIN].items():
                            if isinstance(entry_data, dict) and 'mqtt_manager' in entry_data:
                                mqtt_manager = entry_data['mqtt_manager']
                                if hasattr(mqtt_manager, '_client_id') and mqtt_manager._client_id == self.client_id:
                                    ip_address = entry_data.get('ip_address')
                                    port = entry_data.get('port', 36669)
                                    found_config = True
                                    entry_id_used = entry_id
                                    _LOGGER.debug(f"MQTT Debug: Found TV by mqtt_manager client_id: entry_id={entry_id}, ip_address={ip_address}, port={port}")
                                    break
                    
                    # Third search method: Look for any IP in any entry
                    if not found_config:
                        for entry_id, entry_data in self.hass.data[DOMAIN].items():
                            if isinstance(entry_data, dict) and 'ip_address' in entry_data:
                                ip_address = entry_data['ip_address']
                                if 'port' in entry_data:
                                    port = entry_data['port']
                                found_config = True
                                entry_id_used = entry_id
                                _LOGGER.debug(f"MQTT Debug: Using first TV with IP found: entry_id={entry_id}, ip_address={ip_address}, port={port}")
                                break
                    
                    # Fallback: Use default values from const.py
                    if not found_config:
                        from .const import DEFAULT_IP, DEFAULT_PORT
                        _LOGGER.warning(f"MQTT Debug: Could not find TV configuration for {self.client_id}, using default IP and port")
                        ip_address = DEFAULT_IP
                        port = DEFAULT_PORT
                    
                    # Add detailed connection debugging
                    _LOGGER.debug(f"MQTT Connection Details:")
                    _LOGGER.debug(f"- Client ID: {self.client_id}")
                    _LOGGER.debug(f"- Username: {self.username}")
                    _LOGGER.debug(f"- IP Address: {ip_address}")
                    _LOGGER.debug(f"- Port: {port}")
                    _LOGGER.debug(f"- Config Entry ID used: {entry_id_used}")
                    _LOGGER.debug(f"- Using SSL: {os.path.exists(cert_file) and os.path.exists(key_file)}")
                    _LOGGER.debug(f"- Certificate Path: {cert_file}")
                    _LOGGER.debug(f"- Key Path: {key_file}")
                    
                    _LOGGER.debug(f"Connecting to MQTT broker at {ip_address}:{port}")
                    client.connect_async(ip_address, port, keepalive=60)
                    client.loop_start()
                    
                    # Wait for publish to complete or time out
                    timeout = 10  # 10 seconds timeout
                    start_time = time.time()
                    while not publish_completed.is_set() and (time.time() - start_time) < timeout:
                        time.sleep(0.1)
                    
                    # Clean up
                    client.loop_stop()
                    client.disconnect()
                    
                    if result:
                        _LOGGER.debug("Message published successfully")
                    else:
                        _LOGGER.error("Publish failed or timed out")
                    
                    return result
                    
                except Exception as connect_ex:
                    _LOGGER.error(f"Connection error: {connect_ex}")
                    return False
            
            except Exception as ex:
                _LOGGER.error(f"Error in MQTT operation: {ex}")
                return False
        
        try:
            # Run the MQTT operations in a separate thread
            return await self.hass.async_add_executor_job(mqtt_publish_in_thread)
                
        except Exception as ex:
            _LOGGER.error(f"Error in async MQTT operation: {ex}")
            return False
