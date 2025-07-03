import os
import logging
import ssl
import paho.mqtt.client as mqtt
import threading
import time

try:
    TLS_VERSION = ssl.PROTOCOL_TLS
except AttributeError:
    TLS_VERSION = ssl.PROTOCOL_TLSv1

logger = logging.getLogger(__name__)


class HomemateMQTTHost:

    CONFIGURABLE_OPTIONS = [
        "mqtt_client_id",
        "mqtt_username",
        "mqtt_password",
        "mqtt_host",
        "mqtt_port",
        "mqtt_tls_cacert",
        "mqtt_tls_certfile",
        "mqtt_tls_keyfile",
        "discovery_prefix",
        "node_id"
    ]

    def __init__(self):
        self.mqtt_client = None
        self.discovery_prefix = "homeassistant"
        self.node_id = None

        self.mqtt_client_id = ""

        self.mqtt_username = None
        self.mqtt_password = None

        self.mqtt_host = "localhost"
        self.mqtt_port = 1883

        self.mqtt_tls_cacert = None
        self.mqtt_tls_certfile = None
        self.mqtt_tls_keyfile = None

        self._connected = False
        self._pending_devices = []

        self._healthcheck_interval = 30  # seconds
        self._pingresp_timeout = 60      # seconds
        self._last_pingresp = time.time()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog_running = False

    def add_device(self, device):
        if self._connected:
            device.connect(self.mqtt_client, self.discovery_prefix, self.node_id)
        else:
            self._pending_devices.append(device)

    def _watchdog_loop(self):
        logger.info("MQTT watchdog started")
        while self._watchdog_running:
            time.sleep(self._healthcheck_interval)
            if self._connected and (time.time() - self._last_pingresp > self._pingresp_timeout):
                logger.warning("No PINGRESP received from MQTT broker in timeout window, attempting reconnect...")
                try:
                    self.mqtt_client.disconnect()
                except Exception as disc_e:
                    logger.error(f"Watchdog disconnect failed: {disc_e}")
                self._last_pingresp = time.time()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            logger.info("Connected to MQTT broker")
            while len(self._pending_devices) > 0:
                device = self._pending_devices.pop()
                self.add_device(device)
        else:
            logger.warning("Connection error: {}".format(rc))

    def _on_disconnect(self, client, userdata, rc):
        logger.warning("Disconnected from broker")
        if self._connected:
            logger.info("Reconnecting to broker...")
            self.reconnect()

    def reconnect(self):
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)

    def _on_log(self, client, userdata, level, buf):
        logger.debug("MQTT log: {}".format(buf))
        if buf.startswith("Received "):
            rtype = buf.split(" ", 3)[1]
            if rtype in ["PINGRESP", "SUBACK", "PUBLISH"]:
                self._last_pingresp = time.time()

    def start(self, block=True):
        if self.mqtt_client is None:
            self.mqtt_client = mqtt.Client(
                client_id=self.mqtt_client_id,
                clean_session=self.mqtt_client_id == ""
            )

            self.mqtt_client.on_connect = self._on_connect
            self.mqtt_client.on_disconnect = self._on_disconnect
            self.mqtt_client.on_log = self._on_log

            if self.mqtt_username is not None:
                self.mqtt_client.username_pw_set(
                    self.mqtt_username, self.mqtt_password
                )

            if self.mqtt_tls_cacert is None and self.mqtt_tls_certfile is not None:
                logger.warning("mqtt_tls_cacert not set, ignoring mqtt_tls_certfile setting")
            elif self.mqtt_tls_cacert is not None:
                self.mqtt_client.tls_set(
                    ca_certs=self.mqtt_tls_cacert,
                    keyfile=self.mqtt_tls_keyfile,
                    certfile=self.mqtt_tls_certfile,
                    tls_version=TLS_VERSION
                )

        if not self._watchdog_running:
            self._watchdog_running = True
            self._watchdog_thread.start()

        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)

        if block:
            self.mqtt_client.loop_forever()
        else:
            self.mqtt_client.loop_start()

    def stop(self):
        self._watchdog_running = False
        if self.mqtt_client is not None:
            self.mqtt_client.loop_stop()

    def _prep_config_val(self, arg, value):
        if arg == "mqtt_port":
            return int(value)
        else:
            return value

    def configure_from_args(self, args):
        vargs = vars(args)
        for arg in self.CONFIGURABLE_OPTIONS:
            if arg in vargs and vargs[arg] is not None:
                setattr(self, arg, vargs[arg])

    def configure_from_env(self, prefix=""):
        for arg in self.CONFIGURABLE_OPTIONS:
            arg_key = prefix + arg.upper()
            if arg_key in os.environ:
                setattr(self, arg, self._prep_config_val(arg, os.environ[arg_key]))

    def configure_from_docker_secrets(self):
        for arg in self.CONFIGURABLE_OPTIONS:
            spath = os.path.join('/run/secrets', arg)
            if os.path.exists(spath):
                value = open(spath).read().strip()
                setattr(self, arg, self._prep_config_val(arg, value))

    @classmethod
    def add_argparse_params(cls, parser):
        parser.add_argument("--mqtt-client-id", default=None, required=False)
        parser.add_argument("--mqtt-username", default=None, required=False)
        parser.add_argument("--mqtt-password", default=None, required=False)
        parser.add_argument("--mqtt-host", default=None, required=False)
        parser.add_argument("--mqtt-port", default=None, type=int, required=False)
        parser.add_argument("--mqtt-tls-cacert", default=None, required=False)
        parser.add_argument("--mqtt-tls-certfile", default=None, required=False)
        parser.add_argument("--mqtt-tls-keyfile", default=None, required=False)

        parser.add_argument("--discovery-prefix", default=None, required=False)
        parser.add_argument("--node-id", default=None, required=False)
