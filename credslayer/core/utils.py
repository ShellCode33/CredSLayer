# coding: utf-8

import base64
import re
from collections import namedtuple

from string import printable as printable_charset
from typing import List, Tuple

from pyshark.packet.packet import Packet

CreditCard = namedtuple("CreditCard", ['name', 'number'])
STRING_EXTRACT_REGEX = re.compile(b"[^" + printable_charset.encode() + b"]+")


class Credentials(object):

    """
    This object represents credentials found in network captures. CredSLayer considers two forms of credentials :
    the classic pair username/password and hashes (that can be cracked or used in pass-the-hash attacks).

    Attributes
    ----------
    username : str
    password : str
    hash : str
    context : dict
        Contains information on how/where the credentials can be used.
    """

    def __init__(self, username=None, password=None, hash=None, context=None):
        self.username = username
        self.password = password
        self.hash = hash
        self.context = context if context else {}

    def __eq__(self, other):

        if not isinstance(other, Credentials):
            raise ValueError("Unsupported comparison")

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

    def __bool__(self):
        """
        Whether the credentials should be considered empty or not.
        """
        return self.username is not None \
            or self.password is not None \
            or self.hash is not None


def extract_strings_from(packet: Packet) -> List[str]:
    """
    Desesparately tries to extract strings from a packet raw bytes.

    Parameters
    ----------
    packet : Packet
        The `Packet` to extract strings from.

    Returns
    -------
    List[str]
        The strings found in the packet.
    """

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
    """
    Builds a list of strings that are separated by a new line character (i.e. \r \n and \0).
    It's very useful when trying to extract data while limiting false positives.
    """

    strings = extract_strings_from(packet)
    strings = "".join(strings)
    return re.split(r"[\r\n\x00]+", strings)


def parse_sasl_creds(base64_encoded, sasl_type) -> Tuple[str, str]:
    """
    This function aims to parse SASL auth tokens.
    https://tools.ietf.org/html/rfc4616

    Parameters
    ----------
    base64_encoded
        The input containing the SASL payload.

    sasl_type
        The SASL auth mechanism, only PLAIN is supported for now.

    Returns
    -------
    Tuple
        Of username and password.

    Raises
    ------
    TypeError
        If the auth mechanism is not supported.
    """
    if sasl_type == "PLAIN":
        auth_content = base64.b64decode(base64_encoded)
        auth_content = auth_content.split(b"\x00")
        username = auth_content[1].decode()
        password = auth_content[2].decode()
        return username, password

    else:
        raise TypeError("SASL auth type not supported: " + sasl_type)
