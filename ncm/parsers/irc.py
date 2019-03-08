# coding: utf-8

from scapy.plist import PacketList
from ncm.core import logger, utils
from ncm.core.utils import CredentialsList, Credentials
import re


def analyse(packets: PacketList) -> CredentialsList:

    logger.debug("IRC analysis...")

    nick = None
    all_credentials = []
    strings = utils.extract_strings_splitted_on_new_lines_from(packets)

    for string in strings:
        tokens = string.split(" ")

        if tokens[0] == "NICK":
            if nick:
                all_credentials.append(Credentials(nick))

            nick = tokens[1]

        match = re.search(r":IDENTIFY (.+?)", string, re.IGNORECASE)

        if match:
            all_credentials.append(Credentials(nick, match[1]))
            nick = None

        if tokens[0] == "OPER":
            username = tokens[1]
            password = " ".join(tokens[2:])  # Password could contain spaces
            all_credentials.append(Credentials(username, password))

    if nick:
        all_credentials.append(Credentials(nick))

    return all_credentials
