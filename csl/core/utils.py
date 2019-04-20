# coding: utf-8
import base64
import re
from collections import namedtuple
from string import printable as printable_charset
from typing import List

from pyshark.packet.packet import Packet

CreditCard = namedtuple("CreditCard", ['name', 'number'])
STRING_EXTRACT_REGEX = re.compile(b"[^" + printable_charset.encode() + b"]+")


class Credentials(object):

    def __init__(self, username=None, password=None, hash=None, context=None):
        self.username = username
        self.password = password
        self.hash = hash
        self.context = context if context else {}

    def __eq__(self, other):

        for item in self.context:
            if item not in other.context or self.context[item] != other.context[item]:
                return False

        return self.username == other.username \
               and self.password == other.password \
               and self.hash == other.hash

    def __repr__(self):
        string = ""

        if self.username:
            string += self.username + " -- "

        if self.password:
            string += self.password + " -- "

        if self.hash:
            string += self.hash + " -- "

        if self.context:
            string += str(self.context) + " -- "

        return string[:-4]

    def is_empty(self):
        return self.username is None and self.password is None and self.hash is None


def extract_strings_from(packet: Packet) -> List[str]:
    if "tcp" not in packet or not hasattr(packet["tcp"], "payload"):
        return []

    strings = []
    load = bytes([int(byte, 16) for byte in packet["tcp"].payload.split(":")])

    try:
        string = load.decode()

        if len(string) > 0:
            strings.append(string)

    except UnicodeDecodeError:
        # We try to split on non-printable bytes and ...
        potential_strings = re.split(STRING_EXTRACT_REGEX, load)

        for potential_string in potential_strings:
            try:
                string = potential_string.decode()

                if len(string) > 3:  # ... we extract strings at least 4 characters long
                    strings.append(string)

            except UnicodeDecodeError:
                pass

    return strings


def extract_strings_splitted_on_end_of_line_from(packet: Packet) -> List[str]:
    """Builds a list of strings that are separated by a new line character.
    It's very useful when trying to extract data while limiting false positives.
    """

    strings = extract_strings_from(packet)
    strings = "".join(strings)
    return re.split("[\r\n\x00]+", strings)


# https://tools.ietf.org/html/rfc4616
def parse_sasl_creds(base64_encoded, type) -> (str, str):
    if type == "PLAIN":
        auth_content = base64.b64decode(base64_encoded)
        auth_content = auth_content.split(b"\x00")
        username = auth_content[1].decode()
        password = auth_content[2].decode()
        return username, password

    else:
        raise Exception("SASL auth type not supported: " + type)
