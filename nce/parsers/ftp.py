# coding: utf-8

from nce.core import logger
import re


def parse(packets):
    logger.debug("FTP analysis...")

    strings = ""

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        # We only want strings, no need to parse bytes with telnet
        try:
            string = packet.load.decode()
            strings += string
        except UnicodeDecodeError:
            continue

    strings = re.split(r"[\n\r]+", strings)

    ftp_confirmed = False
    username = password = None

    # We don't stop the loop even if USER and PASS have been found in case a wrong password has been entered
    # Plus the fact that sometimes the USER statement can be duplicated
    for string in strings:

        # When establishing a new connection to an FTP server, to tell the user the server is ready, it will send a 220
        # We check that to prevent false positives with IRC
        if string.startswith("220"):
            ftp_confirmed = True

        if string.startswith("USER"):
            space_index = string.find(" ")
            username = string[space_index+1:]

        elif string.startswith("PASS"):
            space_index = string.find(" ")
            password = string[space_index + 1:]

    if not ftp_confirmed:
        return None, None

    return username, password
