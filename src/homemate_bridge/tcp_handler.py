import socketserver
import random
import string
import time
import logging
from .packet import HomematePacket, PacketLog
from .devices import HomemateSwitch, HomematePowerSensor
from .const import MAGIC, ID_UNSET, CMD_SERVER_SENDS

logger = logging.getLogger(__name__)

class HomemateTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    _broker = None
    _initial_keys = {}
    _device_settings = {}

    def __init__(self, *args, **kwargs):
        self.switch_id = None
        self.keys = dict(self.__class__._initial_keys.items())

        self.softwareVersion = None
        self.hardwareVersion = None
        self.language = None
        self.modelId = None
        self._switch_on = None
        self.serial = 0
        self.uid = None
        self.entity_id = None
        self.settings = None

        self.power = None
        self.energy_reading_time = None
        
        self._mqtt_switch = None
        self._mqtt_sensors = {
            'power': None,
            'powerFactor': None,
            'current': None,
            'voltage': None,
            'frequency': None,
        }
        super().__init__(*args, **kwargs)

    @property
    def switch_on(self):
        return self._switch_on

    @switch_on.setter
    def switch_on(self, value):
        logger.debug("New switch state: {}".format(value))
        self._switch_on = value
        if self._mqtt_switch is not None:
            self._mqtt_switch.state = self._mqtt_switch.payload_on if value else self._mqtt_switch.payload_off

    def order_state_change(self, new_state):
        if self._switch_on is None:
            return

        payload = {
            "userName": "noone@example.com",
            "uid": self.uid,
            "value1": 0 if self.switch_on else 1,
            "value2": 0,
            "value3": 0,
            "value4": 0,
            "defaultResponse": 1,
            "ver": "2.4.0",
            "qualityOfService": 1,
            "delayTime": 0,
            "cmd": 15,
            "deviceId": self.switch_id.decode("utf-8"),
            "clientSessionId": self.switch_id.decode("utf-8"),
            "order": 'on' if new_state else 'off',
            "serial": self.serial
        }


        packet = HomematePacket.build_packet(
            packet_type=bytes([0x64, 0x6b]),
            key=self.keys[0x64],
            switch_id=self.switch_id,
            payload=payload
        )

        PacketLog.record(packet, PacketLog.OUT, self.keys, self.client_address[0])

        logger.debug("Sending state change for {}, new state {}".format(self.switch_id, new_state))
        logger.debug("Payload: {}".format(payload))

        try:
            self.request.sendall(packet)
        except Exception as e:
            logger.error("Failed to send state change packet: {}".format(e))
            # Let's exit with an error, so the switch will reconnect
            try:
                self.request.close()
            except Exception as close_err:
                logger.error(f"Error closing connection: {close_err}")  
            return


        

    def handle(self):
        # We're supposed to get a heart beat every couple o, close the connection if the switch doesn't send anything in 10 minutes
        self.request.settimeout(60*10)
        logger.debug("Handling connection from {}".format(self.client_address[0]))

        try:
            while True:
                    #multiple packets come in at once, split on the MAGIC bytes
                    data = self.request.recv(1024).strip()
                    packets = data.split( MAGIC )
                    for packet_data in packets[1:]:
                        #add MAGIC bytes back that were lost when splitting the packets
                        packet_data = MAGIC + packet_data
                        self.handle_packet(packet_data)
        except Exception as e:
            logger.error(f"Error receiving data from {self.client_address[0]}: {e}")
            try:
                self.request.close()
            except Exception as close_err:
                logger.error(f"Error closing connection: {close_err}")
    
    def handle_packet(self, packet_data):
        PacketLog.record(packet_data, PacketLog.IN, self.keys, self.client_address[0])
        packet = HomematePacket(packet_data, self.keys)
        logger.debug("Packet from {}: {}".format(self.client_address[0], packet.json_payload))

        if not self._validate_packet(packet):
            return

        if packet.switch_id == ID_UNSET:
            self._handle_handshake_packet(packet)
        if packet.switch_id != self.switch_id:
            self._assign_switch_id(packet)

        self.serial = packet.json_payload['serial']

        if None in (self.entity_id, self.uid) and packet.json_payload['cmd'] not in [0, 6]:
            logger.warning("Handshake not done yet, skipping packet {} from {}".format(packet.json_payload['cmd'], self.client_address[0]))
            return

        response = self._build_response(packet)
        if response is not None:
            response = self.format_response(packet, response)
            logger.debug("Sending response {}".format(response))
            response_packet = HomematePacket.build_packet(
                packet_type=packet.packet_type,
                key=self.keys[packet.packet_type[0]],
                switch_id=self.switch_id,
                payload=response
            )
            PacketLog.record(response_packet, PacketLog.OUT, self.keys, self.client_address[0])
            self.request.sendall(response_packet)

        if packet.json_payload['cmd'] == 32: # Heartbeat
            self._setup_mqtt_devices()
            self.handle_energy_update()

    def _validate_packet(self, packet):
        # Add more validation as needed
        if 'cmd' not in packet.json_payload or 'serial' not in packet.json_payload:
            logger.warning("Malformed packet from {}: missing 'cmd' or 'serial'".format(self.client_address[0]))
            return False
        return True

    def _handle_handshake_packet(self, packet):
        logger.info("Connection from {} is attempting to handshake, generating switch ID".format(self.client_address[0]))
        packet.switch_id = ''.join(
            random.choice(
                string.ascii_lowercase + string.ascii_uppercase + string.digits
            ) for _ in range(32)
        ).encode('utf-8')

    def _assign_switch_id(self, packet):
        logger.info("Assigning switch ID {} to {}".format(packet.switch_id, self.client_address[0]))
        self.switch_id = packet.switch_id

    def _build_response(self, packet):
        if packet.json_payload['cmd'] in self.cmd_handlers:
            return self.cmd_handlers[packet.json_payload['cmd']](packet)
        elif packet.json_payload['cmd'] not in CMD_SERVER_SENDS:
            return self.handle_default(packet)
        else:
            return None

    def _setup_mqtt_devices(self):
        if self._mqtt_switch is None:
            self._mqtt_switch = HomemateSwitch(
                handler=self,
                name=self.settings['name'],
                entity_id=self.entity_id,
                unique_id=self.uid,
            )
            self.__class__._broker.add_device(self._mqtt_switch)
            if self.switch_on is not None:
                self.__class__.switch_on.fset(self, self.switch_on)
        for sensor_type, sensor in self._mqtt_sensors.items():
            if sensor is not None:
                continue
            if sensor_type == 'power':
                self._mqtt_sensors[sensor_type] = HomematePowerSensor(
                    handler=self,
                    entity_name="Power",
                    device_class='power',
                    unit_of_measurement='W',
                    name=self.settings['name'],
                    entity_id=self.entity_id,
                    unique_id=self.uid,
                )
            elif sensor_type == 'powerFactor':
                self._mqtt_sensors[sensor_type] = HomematePowerSensor(
                    handler=self,
                    entity_name="Power Factor",
                    device_class='power_factor',
                    unit_of_measurement='%',
                    fraction_to_percent=True,
                    name=self.settings['name'],
                    entity_id=self.entity_id,
                    unique_id=self.uid,
                )
            elif sensor_type == 'current':
                self._mqtt_sensors[sensor_type] = HomematePowerSensor(
                    handler=self,
                    entity_name="Current",
                    device_class='current',
                    unit_of_measurement='A',
                    name=self.settings['name'],
                    entity_id=self.entity_id,
                    unique_id=self.uid,
                )
            elif sensor_type == 'voltage':
                self._mqtt_sensors[sensor_type] = HomematePowerSensor(
                    handler=self,
                    entity_name="Voltage",
                    device_class='voltage',
                    unit_of_measurement='V',
                    name=self.settings['name'],
                    entity_id=self.entity_id,
                    unique_id=self.uid,
                )
            elif sensor_type == 'frequency':
                self._mqtt_sensors[sensor_type] = HomematePowerSensor(
                    handler=self,
                    entity_name="Frequency",
                    device_class='frequency',
                    unit_of_measurement='Hz',
                    name=self.settings['name'],
                    entity_id=self.entity_id,
                    unique_id=self.uid,
                )
            self.__class__._broker.add_device(self._mqtt_sensors[sensor_type])
        

    def format_response(self, packet, response_payload):
        response_payload['cmd'] = packet.json_payload['cmd']
        response_payload['serial'] = self.serial
        response_payload['status'] = 0

        if 'uid' in packet.json_payload:
            response_payload['uid'] = packet.json_payload['uid']

        return response_payload

    def handle_hello(self, packet):
        for f in ['softwareVersion', 'hardwareVersion', 'language', 'modelId']:
            setattr(self, f, packet.json_payload.get(f, None))

        if 0x64 not in self.keys:
            key = ''.join(
                random.choice(
                    string.ascii_lowercase + string.ascii_uppercase + string.digits
                ) for _ in range(16)
            )
            self.keys[0x64] = key.encode('utf-8')
        else:
            key = self.keys[0x64].decode('utf-8')

        return {
            'key': key
        }

    def handle_default(self, packet):
        # If we don't recognise the packet, just send an "ACK"
        return {}

    def handle_heartbeat(self, packet):
        return {
            'utc': int(time.time())
        }

    def handle_state_update(self, packet):
        if packet.json_payload['statusType'] != 0:
            logger.warning("Got unknown statusType: {}".format(packet.json_payload))

        if packet.json_payload['value1'] == 0:
            self.switch_on = True
        else:
            self.switch_on = False

        return None  # No response to this packet

    def handle_handshake(self, packet):
        if self.settings is None:
            assert 'localIp' in packet.json_payload
            assert 'uid' in packet.json_payload

            localip = packet.json_payload['localIp']
            self.entity_id = localip.replace('.', '_')
            self.uid = packet.json_payload['uid']
            self.settings = self.__class__._device_settings.get(localip, {})
            if 'name' not in self.settings:
                self.settings['name'] = "Homemate Switch " + localip

            logger.debug("Updating device settings for {}: {}".format(self.switch_id, self.settings))
            
        return self.handle_default(packet)

    def handle_energy_update(self, packet=None):
        if self.energy_reading_time is not None and time.time() - self.energy_reading_time < 60:
            # Don't request energy usage if we have a recent reading
            return
        
        payload = {
            "userName": "noone@example.com",
            "uid": self.uid,
            "value1": 0 if self.switch_on else 1,
            "value2": 0,
            "value3": 0,
            "value4": 0,
            "defaultResponse": 1,
            "ver": "2.4.0",
            "qualityOfService": 1,
            "delayTime": 0,
            "cmd": 128,
            "deviceId": self.switch_id.decode("utf-8"),
            "clientSessionId": self.switch_id.decode("utf-8"),
            "serial": self.serial + 1
            }

        packet = HomematePacket.build_packet(
            packet_type=bytes([0x64, 0x6b]),
            key=self.keys[0x64],
            switch_id=self.switch_id,
            payload=payload
        )

        PacketLog.record(packet, PacketLog.OUT, self.keys, self.client_address[0])
        logger.debug("Requesting energy usage: {}".format(payload))
        self.request.sendall(packet)

    def handle_energy_reading(self, packet):
        for sensor_type, sensor in self._mqtt_sensors.items():
            if sensor is None:
                continue
            if sensor_type in packet.json_payload:
                energy_reading = packet.json_payload[sensor_type]
                sensor.report_state(energy_reading)
            else:
                logger.warning("No {} reading in packet: {}".format(sensor_type, packet.json_payload))
        self.energy_reading_time = time.time()    

    @property
    def cmd_handlers(self):
        return {
            0: self.handle_hello,
            32: self.handle_heartbeat,
            42: self.handle_state_update,
            6: self.handle_handshake,
            127: self.handle_energy_update,
            128: self.handle_energy_reading,
            }

    @classmethod
    def set_broker(cls, broker):
        cls._broker = broker

    @classmethod
    def add_key(cls, key_id, key):
        cls._initial_keys[key_id] = key

    @classmethod
    def set_device_settings(cls, settings):
        cls._device_settings = settings
