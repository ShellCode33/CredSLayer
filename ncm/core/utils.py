# coding: utf-8
import base64
import re
from collections import namedtuple
from typing import List
from string import printable as printable_charset
from pyshark.packet.packet import Packet

Credentials = namedtuple('Credentials', ['username', 'password', 'hash'])
Credentials.__new__.__defaults__ = (None,) * len(Credentials._fields)  # Create username and password default values

CreditCard = namedtuple("CreditCard", ['name', 'number'])

STRING_EXTRACT_REGEX = re.compile(b"[^" + printable_charset.encode() + b"]+")


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
