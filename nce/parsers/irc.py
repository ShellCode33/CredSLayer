# coding: utf-8
import re

from nce.core import logger


def parse(packets):
    logger.debug("IRC analysis...")

    username = password = None

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        # We only want strings, no need to parse bytes with telnet
        try:
            string = packet.load.decode()

            match = re.search(r"NICK (.+?)(\r?\n|\s)", string)

            if match:
                username = match[1]

            match = re.search(r":IDENTIFY (.+?)(\r?\n|\s)", string, re.IGNORECASE)

            if match:
                password = match[1]

            match = re.search(r"OPER (.+) (.+?)(\r?\n|\s)", string)

            if match:
                username = match[1]
                password = match[2]

        except UnicodeDecodeError:
                continue

    return username, password
