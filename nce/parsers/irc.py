# coding: utf-8
import re

from nce.core import logger


def analyse(packets):
    logger.debug("IRC analysis...")

    nick = None
    credentials = []

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        # We only want strings, no need to parse bytes with telnet
        try:
            string = packet.load.decode()

            match = re.search(r"NICK (.+?)(\r?\n|\s)", string)

            if match:
                if nick:
                    credentials.append((nick, None))

                nick = match[1]

            match = re.search(r":IDENTIFY (.+?)(\r?\n|\s)", string, re.IGNORECASE)

            if match:
                credentials.append((nick, match[1]))
                nick = None

            match = re.search(r"OPER (.+) (.+?)(\r?\n|\s)", string)

            if match:
                credentials.append((match[1], match[2]))

        except UnicodeDecodeError:
                continue

    if nick:
        credentials.append((nick, None))

    return credentials
