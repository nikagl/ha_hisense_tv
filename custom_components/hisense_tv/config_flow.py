"""Hisense TV config flow."""
import json
import os
import asyncio
import uuid
from json.decoder import JSONDecodeError
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import mqtt
from homeassistant.const import CONF_IP_ADDRESS, CONF_MAC, CONF_NAME, CONF_PIN
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.storage import STORAGE_DIR
from homeassistant.components import wake_on_lan

from .const import (
    CONF_CLIENT_MAC,
    DEFAULT_CLIENT_ID,
    DEFAULT_NAME,
    DEFAULT_PORT,
    DEFAULT_IP,
    DOMAIN,
    CERT_FILE,
    KEY_FILE,
)

_LOGGER = logging.getLogger(__name__)


class HisenseTvFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Hisense TV config flow."""

    VERSION = 1
    task_mqtt = None
    task_auth = None

    def __init__(self):
        """Initialize the config flow."""
        self._mac = None
        self._name = None
        self._ip_address = DEFAULT_IP
        self._port = DEFAULT_PORT
        self._unsubscribe_auth = None
        self._unsubscribe_sourcelist = None
        self._unsubscribe_authcode = None
        self._unsubscribe_tokenissuance = None
        self._unsubscribe_hotelmodechange = None
        self._client_id = DEFAULT_CLIENT_ID
        self._token_data = None
        self._username = None
        self._password = None
        self._timestamp = None
        self._certificates_copied = False
        self._mqtt_client = None
        self._flow_active = True

    async def _check_certificates(self):
        """Check if the required certificate files exist and copy them if not."""
        import aiofiles
        import aiofiles.os
        
        # Create the storage directory if it doesn't exist
        storage_dir = self.hass.config.path(STORAGE_DIR, DOMAIN)
        os.makedirs(storage_dir, exist_ok=True)
        
        # Define the paths for the certificate files
        cert_file = os.path.join(storage_dir, CERT_FILE)
        key_file = os.path.join(storage_dir, KEY_FILE)
        
        # Check if certificates exist in storage directory
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            # Look for certificates in component directory
            component_dir = os.path.dirname(os.path.abspath(__file__))
            source_cert = os.path.join(component_dir, "..", "..", CERT_FILE)
            source_key = os.path.join(component_dir, "..", "..", KEY_FILE)
            
            # Check if certificates exist in parent directories
            if os.path.exists(source_cert) and os.path.exists(source_key):
                # Copy the certificates to the storage directory using async file operations
                await self._async_copy_file(source_cert, cert_file)
                await self._async_copy_file(source_key, key_file)
                
                self._certificates_copied = True
                _LOGGER.debug(f"Certificates copied to {storage_dir}")
                return True
            else:
                _LOGGER.error("Certificate files not found. Please place vidaa_cert.cer and vidaa_cert.pkcs8 in your Home Assistant configuration directory.")
                return False
        
        return True
        
    async def _async_copy_file(self, source, destination):
        """Copy a file asynchronously to avoid blocking the event loop."""
        import aiofiles
        
        async with aiofiles.open(source, "rb") as src_file:
            content = await src_file.read()
            async with aiofiles.open(destination, "wb") as dst_file:
                await dst_file.write(content)

    async def _async_pin_needed(self, message):
        """Handle the authentication message from the TV."""
        _LOGGER.debug("_async_pin_needed - received authentication message: %s", message.payload)
        # In hisense.py, receiving an empty string ('""') means authentication is needed
        if message.payload.decode() == '""':
            _LOGGER.info("Authentication prompt should be displayed on TV, requesting PIN entry")
            # This is GOOD, it means auth flow is working correctly
            self.task_auth = "need_pin"
        else:
            _LOGGER.error("Unexpected authentication response: %s", message.payload)
            self._unsubscribe()
            self.task_auth = False
            
        # Trigger the next step in the flow
        self.hass.async_create_task(
            self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
        )

    async def _async_pin_not_needed(self, message):
        _LOGGER.debug("_async_pin_not_needed")
        self._unsubscribe()
        self.task_auth = True
        self.hass.async_create_task(
            self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
        )

    async def _async_authcode_response(self, message):
        try:
            payload = json.loads(message.payload)
        except JSONDecodeError:
            payload = {}
        _LOGGER.debug("_async_authcode_response %s", payload)
        
        # Only complete auth if result is successful
        if payload.get("result") == 1:
            # After successful authcode, request token
            _LOGGER.debug("Auth code accepted, requesting token")
            
            # Update progress to show we're requesting the token
            self.hass.async_create_task(
                self.hass.config_entries.flow.async_configure(
                    flow_id=self.flow_id, user_input={"progress_action": "auth_token"}
                )
            )
            
            # Close authentication window on TV
            topic_base = f"/remoteapp/tv/ui_service/{self._client_id}/actions/authenticationcodeclose"
            mqtt.publish(
                hass=self.hass,
                topic=topic_base,
                payload="",
            )
            
            # Request the token
            topic_token = f"/remoteapp/tv/platform_service/{self._client_id}/data/gettoken"
            mqtt.publish(
                hass=self.hass,
                topic=topic_token,
                payload='{"refreshtoken": ""}',
            )
        else:
            # If auth failed, update task_auth to trigger reauth with error message
            self._unsubscribe()
            self.task_auth = "invalid_pin"  # Use string to indicate error reason
            self.hass.async_create_task(
                self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
            )

    async def _async_token_received(self, message):
        """Handle token issuance response."""
        _LOGGER.debug("Token received")
        try:
            token_data = json.loads(message.payload)
            _LOGGER.debug("Token data: %s", token_data)
            
            # Extract and store token information
            if "access_token" in token_data and "refresh_token" in token_data:
                # Add expiration time calculation
                import time
                current_time = int(time.time())
                # Default expiration in 24 hours if not provided
                expires_in = token_data.get("expires_in", 86400)
                expires_at = current_time + expires_in
                
                self._token_data = {
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data["refresh_token"],
                    "expires_at": expires_at,
                    "client_id": self._client_id,
                    "username": self._username,
                    # Use access_token as password for subsequent requests
                    "password": token_data["access_token"]
                }
                
                # Test the token by getting TV state
                if await self._test_token():
                    # Successfully received and tested token, complete the flow
                    self._unsubscribe()
                    self.task_auth = True
                    self.hass.async_create_task(
                        self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
                    )
                else:
                    _LOGGER.error("Token test failed")
                    self._token_data = None
                    self._unsubscribe()
                    self.task_auth = "token_test_failed"
                    self.hass.async_create_task(
                        self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
                    )
            else:
                _LOGGER.error("Received token data is incomplete")
                self._token_data = None
                self._unsubscribe()
                self.task_auth = "incomplete_token"
                self.hass.async_create_task(
                    self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
                )
        except JSONDecodeError:
            _LOGGER.error("Could not parse token data")
            self._token_data = None
            # If token parsing failed, update task_auth to trigger reauth
            self._unsubscribe()
            self.task_auth = "invalid_token_data"
            self.hass.async_create_task(
                self.hass.config_entries.flow.async_configure(flow_id=self.flow_id)
            )

    async def _test_token(self):
        """Test the token by getting TV state."""
        _LOGGER.debug("Testing token by getting TV state")
        try:
            # Use the token to get TV state
            if not self._token_data or "access_token" not in self._token_data:
                _LOGGER.error("No access token available for testing")
                return False
                
            # Set up a temporary client with the token as password
            import paho.mqtt.client as mqtt
            import ssl
            import os
            
            test_client = mqtt.Client(client_id=self._client_id)
            test_client.username_pw_set(
                self._username, 
                self._token_data["access_token"]  # Use token as password
            )
            
            # Set up SSL for the test client
            storage_dir = self.hass.config.path(STORAGE_DIR, DOMAIN)
            cert_file = os.path.join(storage_dir, CERT_FILE)
            key_file = os.path.join(storage_dir, KEY_FILE)
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            test_client.tls_set_context(ssl_context)
            test_client.tls_insecure_set(True)
            
            # Connect to TV
            connection_result = asyncio.Future()
            
            def on_connect(client, userdata, flags, rc):
                connection_result.set_result(rc == 0)
            
            test_client.on_connect = on_connect
            
            # Connect and start loop
            test_client.connect(self._ip_address, self._port, keepalive=10)
            test_client.loop_start()
            
            # Wait for connection result
            try:
                result = await asyncio.wait_for(connection_result, timeout=10)
                if result:
                    _LOGGER.debug("Token verification successful")
                    # Request TV state to further verify token
                    request_result = asyncio.Future()
                    
                    def on_message(client, userdata, msg):
                        if "state" in msg.topic:
                            _LOGGER.debug(f"Received state response: {msg.payload}")
                            request_result.set_result(True)
                    
                    test_client.on_message = on_message
                    test_client.subscribe(f"/remoteapp/mobile/{self._client_id}/#")
                    
                    # Send state request
                    test_client.publish(
                        f"/remoteapp/tv/remote_service/{self._client_id}/actions/gettvstate",
                        ''
                    )
                    
                    try:
                        await asyncio.wait_for(request_result, timeout=10)
                        _LOGGER.debug("TV state request successful")
                        return True
                    except asyncio.TimeoutError:
                        _LOGGER.error("TV state request timed out")
                        return False
                else:
                    _LOGGER.error(f"Token verification failed: Connection result {result}")
                    return False
            except asyncio.TimeoutError:
                _LOGGER.error("Connection timeout during token verification")
                return False
            finally:
                test_client.disconnect()
                test_client.loop_stop()
                
        except Exception as ex:
            _LOGGER.error(f"Token test failed with exception: {ex}")
            return False
            
        return False

    def _unsubscribe(self):
        _LOGGER.debug("_unsubscribe")
        if self._unsubscribe_auth is not None:
            self._unsubscribe_auth()
            self._unsubscribe_auth = None
        if self._unsubscribe_sourcelist is not None:
            self._unsubscribe_sourcelist()
            self._unsubscribe_sourcelist = None
        if self._unsubscribe_authcode is not None:
            self._unsubscribe_authcode()
            self._unsubscribe_authcode = None
        if self._unsubscribe_tokenissuance is not None:
            self._unsubscribe_tokenissuance()
            self._unsubscribe_tokenissuance = None
        if self._unsubscribe_hotelmodechange is not None:
            self._unsubscribe_hotelmodechange()
            self._unsubscribe_hotelmodechange = None

    @staticmethod
    def cross_sum(n):
        """Sum all digits of a number."""
        return sum(int(digit) for digit in str(n))

    @staticmethod
    def string_to_hash(input_str):
        """Convert a string to a hash."""
        import hashlib
        return hashlib.md5(input_str.encode("utf-8")).hexdigest().upper()

    def random_mac_address(self):
        """Generate a random MAC address as per hisense.py implementation."""
        import random
        # A MAC address has 6 pairs of hexadecimal digits
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        return ':'.join(f'{octet:02x}' for octet in mac)

    def define_hashes(self, mac=None, timestamp=None):
        """Define the hashes, username, password, and client_id."""
        import time

        self._timestamp = timestamp or int(time.time())

        # If no MAC is provided or it's None, generate a random one
        if not mac:
            mac = self.random_mac_address()
            _LOGGER.debug(f"Generated random MAC address: {mac}")

        _LOGGER.debug(f"Using MAC Address: {mac}")

        # **** MODIFIED TO MATCH HISENSE.PY EXACTLY ****
        # Calculate the hashes EXACTLY as in hisense.py
        first_hash = self.string_to_hash("&vidaa#^app")
        _LOGGER.debug(f"First Hash: {first_hash}")
        
        # This is the hard-coded hash from hisense.py - don't use first_hash
        second_hash = self.string_to_hash(f"38D65DC30F45109A369A86FCE866A85B${mac}")
        _LOGGER.debug(f"Second Hash: {second_hash}")
        
        last_digit_of_cross_sum = self.cross_sum(self._timestamp) % 10
        _LOGGER.debug(f"Last digit of cross sum: {last_digit_of_cross_sum}")
        
        third_hash = self.string_to_hash(f"his{last_digit_of_cross_sum}h*i&s%e!r^v0i1c9")
        _LOGGER.debug(f"Third Hash: {third_hash}")
        
        fourth_hash = self.string_to_hash(f"{self._timestamp}${third_hash[:6]}")
        _LOGGER.debug(f"Fourth Hash: {fourth_hash}")

        self._username = f"his${self._timestamp}"
        _LOGGER.debug(f"Using username: {self._username}")
            
        self._password = fourth_hash
        self._client_id = f"{mac}$his${second_hash[:6]}_vidaacommon_001"

        _LOGGER.debug(f"Username: {self._username}")
        _LOGGER.debug(f"Password: {self._password}")
        _LOGGER.debug(f"Client ID: {self._client_id}")

        return self._client_id

    async def async_step_user(self, user_input=None) -> FlowResult:
        """Handle the initial step of the config flow."""
        # If authentication is complete, move to next step
        if self.task_auth is True:
            _LOGGER.debug("async_step_user - task_auth is True")
            return self.async_show_progress_done(next_step_id="finish")

        # If authentication requires PIN, move to auth step
        if isinstance(self.task_auth, str) and self.task_auth == "need_pin":
            _LOGGER.debug("async_step_user - task_auth is need_pin -> auth step")
            return self.async_show_progress_done(next_step_id="auth")

        # If authentication failed, abort
        if self.task_auth is False:
            self.task_auth = None
            _LOGGER.debug("async_step_user - task_auth is False -> aborting")
            return self.async_abort(reason="cannot_connect")

        # If first time or validation failed, show the form
        if user_input is None:
            _LOGGER.debug("async_step_user - user_input is None")
            # Use string literals for field names to ensure translations work properly
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema(
                    {
                        vol.Required("name", default=DEFAULT_NAME): str,
                        vol.Optional("mac"): str,  # TV's MAC address (optional for WOL)
                        vol.Optional("client_mac"): str,  # Client MAC address (optional)
                        vol.Optional("timestamp", default=0): int,  # Add timestamp field
                        vol.Required("ip_address", default=DEFAULT_IP): str,
                        vol.Optional("port", default=DEFAULT_PORT): int,  # Add port field
                    }
                ),
                description_placeholders={
                    "mac_info": "Leave Client MAC field empty to use a randomly generated one. TV MAC is only needed for Wake-on-LAN."
                }
            )

        # Store user input and proceed with setup
        _LOGGER.debug("async_step_user - processing user input")
        _LOGGER.debug(f"User input: {user_input}")

        # Store the TV's MAC address (for Wake-on-LAN)
        tv_mac = user_input.get(CONF_MAC) or user_input.get("mac")

        # Get or generate the client MAC address (for authentication)
        client_mac = user_input.get(CONF_CLIENT_MAC) or user_input.get("client_mac")
        if not client_mac or client_mac.strip() == "":
            client_mac = self.random_mac_address()
            _LOGGER.debug(f"Using randomly generated client MAC address: {client_mac}")

        self.task_mqtt = {
            CONF_MAC: tv_mac,  # TV's MAC for WOL
            CONF_CLIENT_MAC: client_mac,  # Client MAC for auth
            CONF_NAME: user_input.get(CONF_NAME) or user_input.get("name"),
            CONF_IP_ADDRESS: user_input.get(CONF_IP_ADDRESS) or user_input.get("ip_address", DEFAULT_IP),
            "port": user_input.get("port", DEFAULT_PORT),  # Store port value
        }

        # Store values for later use
        self._mac = client_mac  # This is the client MAC for auth calculations
        self._name = user_input.get(CONF_NAME) or user_input.get("name")
        self._ip_address = user_input.get(CONF_IP_ADDRESS) or user_input.get("ip_address", DEFAULT_IP)
        self._port = user_input.get("port", DEFAULT_PORT)  # Store port value for later use
        
        # Get custom timestamp if provided
        custom_timestamp = user_input.get("timestamp", 0)
        if custom_timestamp > 0:
            _LOGGER.debug(f"Using custom timestamp: {custom_timestamp}")
            # Add timestamp to task_mqtt data to store it in config entry
            self.task_mqtt["timestamp"] = custom_timestamp

        # Wake-on-LAN - only if TV MAC is provided
        if tv_mac and tv_mac.strip():
            try:
                _LOGGER.debug(f"Attempting Wake-on-LAN with MAC: {tv_mac}")
                # Send multiple WoL packets to ensure TV wakes up
                for _ in range(3):
                    await self.hass.services.async_call(
                        "wake_on_lan", 
                        "send_magic_packet", 
                        {"mac": tv_mac}
                    )
                    await asyncio.sleep(1)
                _LOGGER.debug("Wake-on-LAN packets sent")
                await asyncio.sleep(10)  # Give the TV more time to fully boot
            except Exception as ex:
                _LOGGER.error(f"Error sending Wake-on-LAN packet: {ex}")
        else:
            _LOGGER.debug("No TV MAC provided, skipping Wake-on-LAN")

        # Check if we have the necessary certificates
        if not await self._check_certificates():
            return self.async_abort(reason="missing_certificates")

        # Generate client_id and credentials using client MAC and custom timestamp if provided
        self.define_hashes(self._mac, custom_timestamp if custom_timestamp > 0 else None)

        # Connect to the TV's MQTT broker directly
        if not await self._connect_to_tv_mqtt():
            return self.async_abort(reason="Cannot make an MQTT connection to the TV")

        # Set up authentication check as a task
        self.hass.async_create_task(self._subscribe_and_publish_authentication())

        # Show progress screen with required progress_action parameter
        return self.async_show_progress(
            step_id="user",
            description_placeholders={
                "device_name": self._name
            },
            progress_action="connect",  # Add this required parameter
            progress_task=self.hass.async_create_task(
                self._wait_for_authentication_response()
            )
        )

    async def async_step_reauth(self, user_input=None):
        """Reauth handler."""
        _LOGGER.debug("async_step_reauth: %s", user_input)
        self.task_auth = None
        return await self.async_step_auth(user_input=user_input)

    async def async_step_auth(self, user_input=None):
        """Auth handler."""
        if self.task_auth is True:
            _LOGGER.debug("async_step_auth - task_auth is True -> finish")
            return self.async_show_progress_done(next_step_id="finish")

        # Handle different error types
        if isinstance(self.task_auth, str):
            if self.task_auth == "need_pin":
                # This is not an error, but a request for PIN input
                self.task_auth = None
                _LOGGER.debug("async_step_auth - showing PIN entry form")
                return self.async_show_form(
                    step_id="auth",
                    data_schema=vol.Schema({vol.Required(CONF_PIN): int}),
                    description_placeholders={"message": "Please enter the PIN shown on your TV"}
                )
            else:
                # Handle actual errors
                error = self.task_auth
                self.task_auth = None
                _LOGGER.debug(f"async_step_auth - task_auth error: {error}")
                return self.async_show_form(
                    step_id="auth",
                    data_schema=vol.Schema({vol.Required(CONF_PIN): int}),
                    errors={"base": error}
                )

        if user_input is None:
            self.task_auth = None
            _LOGGER.debug("async_step_auth - user_input is None -> show form")
            return self.async_show_form(
                step_id="auth",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_PIN): int,
                    }
                ),
            )
        else:
            _LOGGER.debug("async_step_auth sending PIN: %s", user_input)
            
            # Show progress during validation with required progress_action
            return self.async_show_progress(
                step_id="auth",
                description_placeholders={"message": "Validating PIN..."},
                progress_action="validate_pin",  # Add this required parameter
                progress_task=self.hass.async_create_task(
                    self._validate_pin(user_input.get(CONF_PIN))
                )
            )

    async def _validate_pin(self, pin):
        """Validate the PIN."""
        # Make sure subscriptions are set up correctly
        if not self._mqtt_client or not hasattr(self._mqtt_client, 'is_connected') or not self._mqtt_client.is_connected():
            _LOGGER.debug("MQTT client not connected, reconnecting")
            await self._connect_to_tv_mqtt()
            # After connecting, set up the necessary subscriptions
            await self._subscribe_for_auth_responses()
        
        # Send authentication code to TV
        payload = json.dumps({"authNum": pin})
        _LOGGER.debug(f"Publishing authentication code: {payload}")
        
        # Define the topic path for sending the authentication code
        topic = f"/remoteapp/tv/ui_service/{self._client_id}/actions/authenticationcode"
        
        # Publish using MQTT
        if self._mqtt_client and hasattr(self._mqtt_client, 'publish'):
            self._mqtt_client.publish(topic, payload)
            _LOGGER.debug(f"Published PIN to {topic}")
        else:
            # Fall back to HA's MQTT service if direct client isn't available
            mqtt.publish(
                hass=self.hass,
                topic=topic,
                payload=payload,
            )
            _LOGGER.debug(f"Published PIN via HA MQTT service to {topic}")
        
        # Wait for authentication response
        await self._wait_for_authentication_response()

    async def async_step_finish(self, user_input=None):
        """Finish config flow."""
        _LOGGER.debug("async_step_finish")
        
        # If we have token data, add it to the entry
        entry_data = dict(self.task_mqtt)
        if self._token_data:
            entry_data.update(self._token_data)
            
            # Use the access token as the password for future authentication
            entry_data["password"] = self._token_data["access_token"]
        
        return self.async_create_entry(
            title=self.task_mqtt[CONF_NAME], 
            data=entry_data
        )

    async def async_step_import(self, data):
        """Handle import from YAML."""
        _LOGGER.debug("async_step_import")
        return self.async_create_entry(title=data[CONF_NAME], data=data)

    async def _subscribe_and_publish_authentication(self):
        """Subscribe to topics and publish authentication messages."""
        _LOGGER.debug("Setting up authentication with Client ID: %s", self._client_id)
        topicTVUIBasepath = f"/remoteapp/tv/ui_service/{self._client_id}/"
        topicTVPSBasepath = f"/remoteapp/tv/platform_service/{self._client_id}/"
        topicMobiBasepath = f"/remoteapp/mobile/{self._client_id}/"
        topicBrcsBasepath = f"/remoteapp/mobile/broadcast/"
        topicRemoBasepath = f"/remoteapp/tv/remote_service/{self._client_id}/"

        # Use the existing MQTT client instead of creating a new one
        try:
            import ssl
            import os
            import time
            
            # Ensure we have a valid MQTT client
            if not self._mqtt_client or not hasattr(self._mqtt_client, 'is_connected') or not self._mqtt_client.is_connected():
                _LOGGER.debug("MQTT client not connected, reconnecting")
                await self._connect_to_tv_mqtt()
                
            if not self._mqtt_client:
                _LOGGER.error("Failed to create MQTT client")
                self.task_auth = False
                return
            
            # Set up message handlers for authentication flow
            auth_future = asyncio.Future()
            authcode_future = asyncio.Future()
            token_future = asyncio.Future()
            
            # Store original callbacks to restore later if needed
            original_on_message = self._mqtt_client.on_message
            original_on_disconnect = self._mqtt_client.on_disconnect
            
            # Flag to track if the flow is still active
            self._flow_active = True
            
            def on_message(client, userdata, msg):
                _LOGGER.debug(f"Message received on topic {msg.topic}: {msg.payload}")
                
                # Safety check: Don't process messages if flow is no longer active
                if not self._flow_active:
                    _LOGGER.debug("Flow is no longer active, ignoring message")
                    return
                
                # Use exact topic matching to avoid confusion between similar topics
                if msg.topic.endswith('/ui_service/data/authentication') and not 'authenticationcode' in msg.topic:
                    # Authentication message received
                    payload = msg.payload.decode()
                    _LOGGER.debug(f"Authentication message: {payload}")
                    
                    if payload == '""':
                        _LOGGER.info("Authentication prompt should be displayed on TV")
                        # IMPORTANT: Just set the task_auth state and DON'T try to advance the flow here
                        # Let the _wait_for_authentication_response method handle the flow progression
                        self.task_auth = "need_pin"
                        if not auth_future.done():
                            auth_future.set_result(True)
                    else:
                        _LOGGER.error(f"Unexpected authentication message: {payload}")
                        self.task_auth = False
                        if not auth_future.done():
                            auth_future.set_result(False)
                
                elif 'ui_service/data/authenticationcode' in msg.topic:
                    # Authentication code response
                    try:
                        payload = json.loads(msg.payload)
                        _LOGGER.debug(f"Auth code response: {payload}")
                        
                        if payload.get("result") == 1:
                            _LOGGER.info("Authentication code accepted")
                            if not authcode_future.done():
                                authcode_future.set_result(True)
                                
                            # Close authentication window - only proceed if flow is still active
                            if self._flow_active:
                                # Close authentication window
                                client.publish(f"/remoteapp/tv/ui_service/{self._client_id}/actions/authenticationcodeclose", "")
                                
                                # Request token
                                token_request = '{"refreshtoken": ""}'
                                _LOGGER.debug(f"Requesting token with: {token_request}")
                                client.publish(f"/remoteapp/tv/platform_service/{self._client_id}/data/gettoken", token_request)
                                
                                # Safety mechanism: Don't try to update UI if flow might be completed
                                try:
                                    self.hass.async_create_task(
                                        self.hass.config_entries.flow.async_configure(
                                            flow_id=self.flow_id, user_input={"progress_action": "auth_token"}
                                        )
                                    )
                                except Exception as ex:
                                    _LOGGER.debug(f"Could not update flow progress: {ex}")
                        else:
                            _LOGGER.error(f"Auth code rejected: {payload}")
                            self.task_auth = "invalid_pin"
                            if not authcode_future.done():
                                authcode_future.set_result(False)
                    except json.JSONDecodeError:
                        _LOGGER.error(f"Failed to parse auth code response: {msg.payload}")
                        self.task_auth = "invalid_json"
                        if not authcode_future.done():
                            authcode_future.set_result(False)
                
                elif 'platform_service/data/tokenissuance' in msg.topic:
                    # Token received
                    try:
                        token_data = json.loads(msg.payload)
                        _LOGGER.debug(f"Token received: {token_data}")
                        
                        # Only proceed if we actually have tokens
                        if "accesstoken" in token_data and "refreshtoken" in token_data:
                            # Add expiration time calculation
                            import time
                            current_time = int(time.time())
                            # Default expiration in 24 hours if not provided
                            expires_in = token_data.get("expires_in", 86400)
                            expires_at = current_time + expires_in
                            
                            self._token_data = {
                                "access_token": token_data.get("accesstoken"),
                                "refresh_token": token_data.get("refreshtoken"),
                                "expires_at": expires_at,
                                "client_id": self._client_id,
                                "username": self._username,
                                "password": token_data.get("accesstoken")  # Use access_token as password
                            }
                            
                            # Set task_auth to true to indicate success
                            self.task_auth = True
                            if not token_future.done():
                                token_future.set_result(True)
                        else:
                            _LOGGER.error("Token data is missing required fields")
                            self.task_auth = "invalid_token_data"
                            if not token_future.done():
                                token_future.set_result(False)
                    except json.JSONDecodeError:
                        _LOGGER.error(f"Failed to parse token response: {msg.payload}")
                        self.task_auth = "invalid_token_data"
                        if not token_future.done():
                            token_future.set_result(False)
            
            def on_disconnect(client, userdata, rc):
                _LOGGER.debug(f"Disconnected with result code: {rc}")
                # Only handle unexpected disconnections
                if rc != 0:
                    _LOGGER.warning("Unexpected disconnection from MQTT broker")
            
            # Set callbacks
            self._mqtt_client.on_message = on_message
            self._mqtt_client.on_disconnect = on_disconnect
            
            # Make EXACT subscription order as in hisense.py
            self._mqtt_client.subscribe([
                (topicBrcsBasepath + 'ui_service/state', 0),
                (topicTVUIBasepath + 'actions/vidaa_app_connect', 0),
                (topicMobiBasepath + 'ui_service/data/authentication', 0),
                (topicMobiBasepath + 'ui_service/data/authenticationcode', 0),
                (topicBrcsBasepath + "ui_service/data/hotelmodechange", 0),
                (topicMobiBasepath + 'platform_service/data/tokenissuance', 0),
            ])
            
            # Log all subscriptions in exact order
            _LOGGER.debug(f"Subscribed to {topicBrcsBasepath}ui_service/state")
            _LOGGER.debug(f"Subscribed to {topicTVUIBasepath}actions/vidaa_app_connect")
            _LOGGER.debug(f"Subscribed to {topicMobiBasepath}ui_service/data/authentication")
            _LOGGER.debug(f"Subscribed to {topicMobiBasepath}ui_service/data/authenticationcode")
            _LOGGER.debug(f"Subscribed to {topicBrcsBasepath}ui_service/data/hotelmodechange")
            _LOGGER.debug(f"Subscribed to {topicMobiBasepath}platform_service/data/tokenissuance")
            
            # Now publish the app connect message exactly as in hisense.py
            await asyncio.sleep(1)  # Brief pause before publishing
            
            # Important: Use the exact JSON format from hisense.py
            publish_topic = f"{topicTVUIBasepath}actions/vidaa_app_connect"
            publish_payload = '{"app_version":2,"connect_result":0,"device_type":"Mobile App"}'
            
            _LOGGER.debug(f"Publishing message to {publish_topic}")
            _LOGGER.debug(f"Published JSON: {publish_payload}")
            
            self._mqtt_client.publish(publish_topic, publish_payload)
                
        except Exception as ex:
            _LOGGER.error(f"Failed to set up authentication: {ex}")
            self.task_auth = False

    async def _wait_for_authentication_response(self):
        """Wait for authentication response."""
        # Wait up to 60 seconds for authentication to complete
        for _ in range(60):
            if self.task_auth is True:
                _LOGGER.debug("Authentication successful, proceeding to finish")
                self._flow_active = False
                return
            
            if isinstance(self.task_auth, str) and self.task_auth == "need_pin":
                _LOGGER.debug("PIN needed, proceeding to auth step")
                return
                
            if self.task_auth is False:
                _LOGGER.debug("Authentication failed")
                self._flow_active = False
                return
                
            await asyncio.sleep(1)
        
        _LOGGER.error("Authentication response timeout after 60 seconds")
        self.task_auth = False
        self._flow_active = False

    @staticmethod
    async def async_check_token_validity(hass, config_entry):
        """Check if the current token is valid or needs refresh."""
        import time
        
        # Get the current data from the config entry
        data = dict(config_entry.data)
        
        # Check if expiration time exists and is approaching
        current_time = int(time.time())
        expires_at = data.get("expires_at", 0)
        
        # If token will expire in the next hour, refresh it
        if expires_at - current_time < 3600:
            _LOGGER.debug("Token is expiring soon, refreshing")
            new_token_data = await HisenseTvFlow.async_refresh_token(hass, data)
            
            if new_token_data:
                # Update the config entry with new token data
                new_data = {**data, **new_token_data}
                hass.config_entries.async_update_entry(
                    config_entry,
                    data=new_data
                )
                _LOGGER.debug("Token refreshed successfully")
                return True
            else:
                _LOGGER.error("Failed to refresh token")
                return False
        
        return True
        
    @staticmethod
    async def async_refresh_token(hass, data):
        """Refresh the token using the refresh token."""
        _LOGGER.debug("Refreshing token")
        
        try:
            # Extract necessary data
            client_id = data.get("client_id")
            username = data.get("username")
            refresh_token = data.get("refresh_token")
            ip_address = data.get(CONF_IP_ADDRESS, DEFAULT_IP)
            port = data.get("port", DEFAULT_PORT)
            
            if not all([client_id, username, refresh_token, ip_address]):
                _LOGGER.error("Missing required data for token refresh")
                return None
                
            # Set up SSL and MQTT client
            import paho.mqtt.client as mqtt
            import ssl
            import os
            
            storage_dir = hass.config.path(STORAGE_DIR, DOMAIN)
            cert_file = os.path.join(storage_dir, CERT_FILE)
            key_file = os.path.join(storage_dir, KEY_FILE)
            
            # Create the refresh client
            refresh_client = mqtt.Client(client_id=client_id)
            refresh_client.username_pw_set(username, refresh_token)
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            refresh_client.tls_set_context(ssl_context)
            refresh_client.tls_insecure_set(True)
            
            # Set up connection and message handling
            token_result = asyncio.Future()
            
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    _LOGGER.debug("Connected to TV for token refresh")
                    client.subscribe(f"/remoteapp/mobile/{client_id}/platform_service/data/tokenissuance")
                else:
                    _LOGGER.error(f"Failed to connect for token refresh: {rc}")
                    if not token_result.done():
                        token_result.set_result(None)
            
            def on_message(client, userdata, msg):
                if "tokenissuance" in msg.topic:
                    try:
                        token_data = json.loads(msg.payload)
                        _LOGGER.debug(f"Received token data: {token_data}")
                        
                        # Handle both "accesstoken" and "access_token" formats
                        access_token = token_data.get("accesstoken") or token_data.get("access_token")
                        refresh_token = token_data.get("refreshtoken") or token_data.get("refresh_token")
                        
                        if access_token and refresh_token:
                            # Calculate expiration time
                            import time
                            current_time = int(time.time())
                            expires_in = token_data.get("expires_in", 86400)
                            expires_at = current_time + expires_in
                            
                            new_token = {
                                "access_token": access_token,
                                "refresh_token": refresh_token,
                                "expires_at": expires_at,
                                "password": access_token  # Update password with new token
                            }
                            if not token_result.done():
                                token_result.set_result(new_token)
                        else:
                            _LOGGER.error(f"Incomplete token data received: {token_data}")
                            if not token_result.done():
                                token_result.set_result(None)
                    except json.decoder.JSONDecodeError:
                        _LOGGER.error("Could not parse token data during refresh")
                        if not token_result.done():
                            token_result.set_result(None)
            
            refresh_client.on_connect = on_connect
            refresh_client.on_message = on_message
            
            # Connect and request token refresh
            refresh_client.connect(ip_address, port, keepalive=10)
            refresh_client.loop_start()
            
            try:
                # Wait for connection and then request token
                await asyncio.sleep(2)  # Give time for connection to establish
                
                # Request token refresh using the refresh token
                refresh_client.publish(
                    f"/remoteapp/tv/platform_service/{client_id}/data/gettoken",
                    json.dumps({"refreshtoken": refresh_token})
                )
                
                # Wait for token result with timeout
                try:
                    result = await asyncio.wait_for(token_result, timeout=30)
                    return result
                except asyncio.TimeoutError:
                    _LOGGER.error("Token refresh timed out")
                    return None
                    
            finally:
                refresh_client.disconnect()
                refresh_client.loop_stop()
                
        except Exception as ex:
            _LOGGER.error(f"Token refresh failed with exception: {ex}")
            return None

    async def _connect_to_tv_mqtt(self):
        """Establish a direct MQTT connection to the TV."""
        import os
        import ssl
        import paho.mqtt.client as mqtt
        
        try:
            # Define the certificate paths
            storage_dir = self.hass.config.path(STORAGE_DIR, DOMAIN)
            cert_file = os.path.join(storage_dir, CERT_FILE)
            key_file = os.path.join(storage_dir, KEY_FILE)
            
            _LOGGER.debug(f"Connecting to TV's MQTT broker at {self._ip_address}:{self._port}")
            _LOGGER.debug(f"Using client_id: {self._client_id}")
            _LOGGER.debug(f"Using username: {self._username}")
            _LOGGER.debug(f"Using password: {self._password}")
            
            # Create a new MQTT client instance EXACTLY like in hisense.py
            # Note the clean_session=True which is important for auth
            self._mqtt_client = mqtt.Client(client_id=self._client_id, clean_session=True, protocol=mqtt.MQTTv311, transport="tcp")
            
            # Set SSL configuration directly as in hisense.py
            self._mqtt_client.tls_set(ca_certs=None, certfile=cert_file, keyfile=key_file, 
                               cert_reqs=mqtt.ssl.CERT_NONE, tls_version=mqtt.ssl.PROTOCOL_TLS)
            self._mqtt_client.tls_insecure_set(True)
            
            # Set auth credentials
            self._mqtt_client.username_pw_set(username=self._username, password=self._password)
            
            # Enable logger for detailed debugging
            self._mqtt_client.enable_logger()
            
            # Set up callbacks
            connection_future = asyncio.Future()
            
            def on_connect(client, userdata, flags, rc):
                _LOGGER.debug(f"MQTT connection result: {rc}")
                if rc == 0:
                    _LOGGER.info("Successfully connected to TV's MQTT broker")
                elif rc == 1:
                    _LOGGER.error("Connection refused - incorrect protocol version")
                elif rc == 2:
                    _LOGGER.error("Connection refused - invalid client identifier")
                elif rc == 3:
                    _LOGGER.error("Connection refused - server unavailable")
                elif rc == 4:
                    _LOGGER.error("Connection refused - bad username or password")
                elif rc == 5:
                    _LOGGER.error("Connection refused - not authorized")
                # Check if the future is already done before setting the result
                if not connection_future.done():
                    connection_future.set_result(rc == 0)
            
            def on_log(client, userdata, level, buf):
                _LOGGER.debug(f"MQTT Log: {buf}")
            
            def on_disconnect(client, userdata, rc):
                _LOGGER.debug(f"Disconnected with result code: {rc}")
            
            self._mqtt_client.on_connect = on_connect
            self._mqtt_client.on_log = on_log
            self._mqtt_client.on_disconnect = on_disconnect
            
            # Connect asynchronously to the TV's MQTT broker - use connect_async like hisense.py
            self._mqtt_client.connect_async(self._ip_address, self._port, keepalive=60)
            
            # Start the MQTT loop in a separate thread
            self._mqtt_client.loop_start()
            
            try:
                # Wait for connection result with timeout
                result = await asyncio.wait_for(connection_future, timeout=15)
                if not result:
                    _LOGGER.error("Failed to connect to TV's MQTT broker")
                    self._mqtt_client.loop_stop()
                    self._mqtt_client.disconnect()
                    return False
                
                _LOGGER.debug(f"Connected to TV's MQTT broker at {self._ip_address}:{self._port}")
                return True
                
            except asyncio.TimeoutError:
                _LOGGER.error("Connection to TV's MQTT broker timed out")
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
                return False
                
        except Exception as ex:
            _LOGGER.error(f"Failed to connect to TV's MQTT broker: {ex}")
            if self._mqtt_client and hasattr(self._mqtt_client, 'is_connected') and self._mqtt_client.is_connected():
                self._mqtt_client.disconnect()
                self._mqtt_client.loop_stop()
            return False
