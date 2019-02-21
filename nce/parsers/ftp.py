# coding: utf-8

from nce.core import logger, utils
import re


def analyse(packets):
    logger.debug("FTP analysis...")

    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    username = password = None
    credentials = []

    # We don't stop the loop even if USER and PASS have been found in case a wrong password has been entered
    # Plus the fact that sometimes the USER statement can be duplicated
    for string in strings:

        # Connection successful (also prevents false positives with IRC)
        if string.startswith("230"):
            credentials.append((username, password))
            username = password = None

        elif string.startswith("USER"):
            space_index = string.find(" ")
            username = string[space_index+1:]

        elif string.startswith("PASS"):
            space_index = string.find(" ")
            password = string[space_index + 1:]

    return credentials
