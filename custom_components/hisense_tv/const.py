"""Hisense TV constants."""
from homeassistant.const import Platform

DOMAIN = "hisense_tv"
PLATFORMS = [Platform.MEDIA_PLAYER, Platform.SENSOR, Platform.SWITCH, Platform.BUTTON]
VERSION = "1.3.6"

DEFAULT_NAME = "Hisense TV"
DEFAULT_PORT = 36669
DEFAULT_IP = "192.168.111.134"
DEFAULT_TIMEOUT = 5
DEFAULT_RETRIES = 3
DEFAULT_MQTT_PREFIX = ""
DEFAULT_CLIENT_ID = ""

# New constant to separate the client MAC from the TV MAC
CONF_CLIENT_MAC = "client_mac"
CONF_MQTT_IN = "mqtt_in"
CONF_MQTT_OUT = "mqtt_out"

SERVER_STATE = "server_state"
SERVER_CERT = "server_cert"

ATTR_CODE = "code"

CERT_FILE = "vidaa_cert.cer"
KEY_FILE = "vidaa_cert.pkcs8"

# Add constants for token management
CONF_USERNAME = "username"
CONF_PASSWORD = "password"  # Used as access_token
CONF_CLIENT_ID = "client_id"
CONF_REFRESH_TOKEN = "refresh_token" 
CONF_EXPIRES_AT = "expires_at"

# Version tracking - increment version
# VERSION is already defined at the top of the file, removing duplicate definition
VERSION_STORAGE_KEY = "version_data"
