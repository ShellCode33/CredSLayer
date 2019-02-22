# coding: utf-8

from scapy.plist import PacketList
from nce.core import logger, utils
from nce.core.utils import CredentialsList, Credentials
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


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("Telnet analysis...")

    all_credentials = []
    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)

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
            begin_pass_index = string.find(":") + 1

            # Prone to false positives, but sometimes the telnet server sends "password:" and sometimes "password: "
            # We're just hoping the password doesn't start with a space...
            if string[begin_pass_index] == " ":
                begin_pass_index += 1

            password = string[begin_pass_index:]

    if username is not None or password is not None:
        all_credentials.append(Credentials(username, password))

    return all_credentials
