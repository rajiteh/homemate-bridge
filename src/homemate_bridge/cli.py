from .tcp_handler import HomemateTCPHandler
from .packet import PacketLog

import socketserver
import json
import logging
import sys
import argparse
import base64
import os

from .mqtt import HomemateMQTTHost

logging.getLogger().setLevel(logging.DEBUG)


logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--homemate-port", type=int, default=10001)
    parser.add_argument("--homemate-interface", default="0.0.0.0")
    parser.add_argument("--keys-file", default=None, required=False)
    parser.add_argument("--devices-file", default=None, required=False)
    parser.add_argument("--packet-log-file", default=None, required=False, help="Log packets to file")
    HomemateMQTTHost.add_argparse_params(parser)
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s - %(message)s")

    if args.keys_file is not None:
        with open(args.keys_file, 'r') as f:
            keys = json.load(f)
            for k, v in keys.items():
                HomemateTCPHandler.add_key(int(k), base64.b64decode(v))
    else:
        logger.warning("Keys file not configured, connections will probably fail!")

    if args.devices_file is not None and os.path.exists(args.devices_file):
        with open(args.devices_file, 'r') as f:
            HomemateTCPHandler.set_device_settings(json.load(f))

    if args.packet_log_file is not None:
        PacketLog.enable(args.packet_log_file)

    host = HomemateMQTTHost()
    host.configure_from_docker_secrets()
    host.configure_from_env()
    host.configure_from_args(args)
    host.start(block=False)
   

    HomemateTCPHandler.set_broker(
        host
    )

    logger.debug("Listening on {}, port {}".format(args.homemate_interface, args.homemate_port))

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((args.homemate_interface, args.homemate_port), HomemateTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    try: 
        server.serve_forever()
    finally:
        server.server_close()
        host.stop()
