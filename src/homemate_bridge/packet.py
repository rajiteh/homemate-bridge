import base64
import json
import struct
import binascii
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from .const import MAGIC


logger = logging.getLogger(__name__)

class HomematePacket:

    def __init__(self, data, keys):
        self.raw = data

        try:
            # Check the magic bytes
            self.magic = data[0:2]
            assert self.magic == MAGIC

            # Check the 'length' field
            self.length = struct.unpack(">H", data[2:4])[0]
            assert self.length == len(data)

            # Check the packet type
            self.packet_type = data[4:6]
            assert self.packet_type == bytes([0x70, 0x6b]) or \
                self.packet_type == bytes([0x64, 0x6b])

            # Check the CRC32
            self.crc = binascii.crc32(data[42:]) & 0xFFFFFFFF
            data_crc = struct.unpack(">I", data[6:10])[0]
            assert self.crc == data_crc
        except AssertionError:
            logger.error("Bad packet:")
            # hexdump(data)
            raise

        self.switch_id = data[10:42]

        self.json_payload = self.decrypt_payload(keys[self.packet_type[0]], data[42:])

    def decrypt_payload(self, key, encrypted_payload):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).decryptor()

        data = decryptor.update(encrypted_payload)

        unpadder = padding.PKCS7(128).unpadder()
        unpad = unpadder.update(data)
        unpad += unpadder.finalize()

        # sometimes payload has an extra trailing null
        if unpad[-1] == 0x00:
            unpad = unpad[:-1]
        return json.loads(unpad.decode('utf-8'))

    @classmethod
    def encrypt_payload(self, key, payload):
        data = payload.encode('utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).encryptor()

        encrypted_payload = encryptor.update(padded_data)
        return encrypted_payload

    @classmethod
    def build_packet(cls, packet_type, key, switch_id, payload):
        encrypted_payload = cls.encrypt_payload(key, json.dumps(payload))
        crc = struct.pack('>I', binascii.crc32(encrypted_payload) & 0xFFFFFFFF)
        length = struct.pack('>H', len(encrypted_payload) + len(MAGIC + packet_type + crc + switch_id) + 2)

        packet = MAGIC + length + packet_type + crc + switch_id + encrypted_payload
        return packet
    
class PacketLog:
    log = []
    logfile = None
    OUT = "out"
    IN = "in"

    @classmethod
    def enable(cls, logfile):
        cls.logfile = logfile

    @classmethod
    def record(cls, data, direction, keys=None, client=None):
        if cls.logfile is not None:
            cls.log.append({
                'data': base64.b64encode(data).decode('utf-8'),
                'direction': direction,
                'keys': {
                    k: base64.b64encode(v).decode('utf-8') for k, v in keys.items()
                },
                'client': client
            })
            with open(cls.logfile, 'w') as f:
                json.dump(cls.log, f)
