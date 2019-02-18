# coding: utf-8

from nce.core import logger


# TODO : this has been tested using cooked mode but not raw mode.

def parse(packets):
    logger.debug("Telnet analysis...")
    strings = []

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        # We only want strings, no need to parse bytes with telnet
        try:
            string = packet.load.decode()
            strings.append(string)
        except UnicodeDecodeError:
            continue

    username = None
    password = None

    for i in range(len(strings)):
        clean_string = strings[i].strip().lower()

        if clean_string.endswith("login:") or clean_string.endswith("username:"):
            username = strings[i+1].replace("\r", "").replace("\n", "")

        elif clean_string.endswith("password:"):
            password = strings[i+1].replace("\r", "").replace("\n", "")

    return username, password
