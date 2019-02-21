# coding: utf-8
import re

from nce.core import logger, utils


def analyse(packets):
    logger.debug("IRC analysis...")

    nick = None
    credentials = []
    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    for string in strings:
        tokens = string.split(" ")

        if tokens[0] == "NICK":
            if nick:
                credentials.append((nick, None))

            nick = tokens[1]

        match = re.search(r":IDENTIFY (.+?)", string, re.IGNORECASE)

        if match:
            credentials.append((nick, match[1]))
            nick = None

        if tokens[0] == "OPER":
            username = tokens[1]
            password = " ".join(tokens[2:])  # Password could contain spaces
            credentials.append((username, password))

    if nick:
        credentials.append((nick, None))

    return credentials
