from hassdevice.devices import Switch, Sensor
import logging

logger = logging.getLogger(__name__)

class HomemateSwitch(Switch):
    def __init__(self, handler, unique_id, **kwargs):
        self._handler = handler
        self.unique_id = unique_id
        super().__init__(**kwargs)

    @Switch.state.setter
    def state(self, value):
        Switch.state.fset(self, value)
        self.client.publish(self.state_topic, value, retain=self.retain)

    @property
    def config(self):
        return {
            'name': "Power",
            'state_topic': self.state_topic,
            'command_topic': self.command_topic,
            'payload_on': self.payload_on,
            'payload_off': self.payload_off,
            'retain': self.retain,
            'unique_id': self.unique_id + "_switch",
            'device': {
                'identifiers': [self.unique_id],
                'name': self.name,
                'manufacturer': "HOMEMATE",
                'model': "HOMEMATE Switch",
            }
        }
    
    def on_state_change(self, new_state):
        logger.debug("Setting new state: {}".format(new_state))
        self._handler.order_state_change(new_state == self.payload_on)

class HomematePowerSensor(Sensor):
    def __init__(self, handler, unique_id, **kwargs):
        self._handler = handler
        self.unique_id = unique_id
        super().__init__(**kwargs)

    @property
    def config(self):
        return {
            'name': "Power",
            'state_topic': self.state_topic,
            'state_class': 'measurement',
            'device_class': 'energy',
            'unit_of_measurement': 'W',
            'unique_id': self.unique_id + "_power",
            'device': {
                'identifiers': [self.unique_id],
                'name': self.name,
                'manufacturer': "HOMEMATE",
                'model': "HOMEMATE Switch",
            }
        }

    def on_energy_usage_change(self, energy_reading):
        logger.debug("Setting new power output: {}".format(energy_reading))
        self.payload_energy_update(energy_reading)
