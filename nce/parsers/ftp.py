# coding: utf-8

from scapy.plist import PacketList
from nce.core import logger, utils
from nce.core.utils import CredentialsList, Credentials
import re


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("FTP analysis...")

    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    username = password = None
    all_credentials = []

    # We don't stop the loop even if USER and PASS have been found in case a wrong password has been entered
    # Plus the fact that sometimes the USER statement can be duplicated
    for string in strings:

        # Connection successful (also prevents false positives with IRC)
        if string.startswith("230") and (username is not None or password is not None):
            all_credentials.append(Credentials(username, password))
            username = password = None

        elif string.startswith("USER"):
            space_index = string.find(" ")
            username = string[space_index+1:]

        elif string.startswith("PASS"):
            space_index = string.find(" ")
            password = string[space_index + 1:]

    return all_credentials
