# coding: utf-8

from nce.core import logger
import re


POTENTIAL_USERNAME_ASK = ["login:", "username:", "user:", "name:"]


def _is_username_duplicated(username):
    """
    Detects if the username has been duplicated because of telnet's echo mode.
    Duplicated username example : aaddmmiinn
    Prone to false positives, but very unlikely. Who uses usernames such as the one above ?..
    """

    if len(username) % 2 == 1:
        return False

    for i in range(0, len(username), 2):
        if username[i] != username[i+1]:
            return False

    return True


def analyse(packets):
    logger.debug("Telnet analysis...")

    credentials = []
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

    strings = re.split(r"[\n\r\x00]+", strings)

    username = password = None

    # We don't stop the loop even if we find a username/password because
    # if we find others it means a wrong password has been entered
    for string in strings:
        potential_username_tokens = string.split(" ")

        # -1 is the username, -2 the "asking" part
        if len(potential_username_tokens) >= 2 and potential_username_tokens[-2] in POTENTIAL_USERNAME_ASK:
            username = potential_username_tokens[-1]

            if _is_username_duplicated(username):
                username = "".join([username[i] for i in range(0, len(username), 2)])

        elif "password:" in string.lower():
            colon_index = string.find(":")
            password = string[colon_index+1:]

    if username is not None or password is not None:
        credentials.append((username, password))

    return credentials
