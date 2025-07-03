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

    def __init__(self, handler, unique_id, entity_name, device_class, unit_of_measurement, clamp_positive=True, fraction_to_percent=False, **kwargs):
        self._handler = handler
        self.unique_id = unique_id
        self.entity_name = entity_name
        self.device_class = device_class
        self.unit_of_measurement = unit_of_measurement
        self.clamp_positive = clamp_positive
        self.fraction_to_percent = fraction_to_percent
        kwargs["entity_id"] += "_" + device_class
        super().__init__(**kwargs)

    def process_value(self, value):
        """
        Process the value before reporting it.
        Override this method in subclasses to customize value processing.
        """
        if value is None:
            return value
        
        value = float(value)
        if self.clamp_positive:
            value = max(0.0, value)

        if self.fraction_to_percent:
            value = value * 100

        return value
    @property
    def config(self):
        return {
            'name': self.entity_name,
            'state_topic': self.state_topic,
            'state_class': 'measurement',
            'device_class': self.device_class,
            'unit_of_measurement': self.unit_of_measurement,
            'unique_id': self.unique_id + "_" + self.device_class,
            'device': {
                'identifiers': [self.unique_id],
                'name': self.name,
                'manufacturer': "HOMEMATE",
                'model': "HOMEMATE Switch",
            }
        }
    
    def report_state(self, energy_reading):
        if self.process_value is not None:
            energy_reading = self.process_value(energy_reading)
        logger.debug("Reporting state for {}: {}".format(self.entity_name, energy_reading))
        self.client.publish(self.state_topic, energy_reading, retain=self.retain)