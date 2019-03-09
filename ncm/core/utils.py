# coding: utf-8

import re
from collections import namedtuple
from typing import List
from string import printable as printable_charset

from scapy.packet import Packet
from scapy.plist import PacketList

Credentials = namedtuple('Credentials', ['username', 'password', 'hash'])
Credentials.__new__.__defaults__ = (None,) * len(Credentials._fields)  # Create username and password default values
CredentialsList = List[Credentials]

CreditCard = namedtuple("CreditCard", ['name', 'number'])

STRING_EXTRACT_REGEX = re.compile(b"[^" + printable_charset.encode() + b"]+")


def session_extractor(pkt: Packet) -> str:
    """Extract sessions from packets.

    By default A talking to B and B answering to A are 2 different sessions. We want them to be the same.
    We simply apply an alphabetic sort on IP:PORT to determine which one will go first in the string.
    """

    if "IP" in pkt:
        pkt_type = "IP"
    elif "IPv6" in pkt:
        pkt_type = "IPv6"
    else:
        return "WeDontCare"

    if not hasattr(pkt[pkt_type], "sport") or not hasattr(pkt[pkt_type], "dport"):
        return "WeDontCare"

    src = "{}:{}".format(pkt[pkt_type].src, pkt[pkt_type].sport)
    dst = "{}:{}".format(pkt[pkt_type].dst, pkt[pkt_type].dport)

    if src < dst:
        return src + " | " + dst
    else:
        return dst + " | " + src


def extract_strings_from(packets: PacketList) -> List[str]:
    """Build a list of strings from packets' payload.
    """

    strings = []

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        try:
            string = packet.load.decode()

            if len(string) > 0:
                strings.append(string)

        except UnicodeDecodeError:
            # If non-unicode data were in the packet's payload, we try to split on non-printable bytes and ...
            potential_strings = re.split(STRING_EXTRACT_REGEX, packet.load)

            for potential_string in potential_strings:
                try:
                    string = potential_string.decode()

                    if len(string) > 3:  # ... we extract strings at least 4 characters long
                        strings.append(string)

                except UnicodeDecodeError:
                    pass

    return strings


def extract_strings_splitted_on_new_lines_from(packets: PacketList) -> List[str]:
    """Builds a list of strings that are separated by a new line character. It's very useful when working with
    text-based protocol that use new lines to delimit messages (IRC, FTP, Telnet, ...).
    """

    strings = extract_strings_from(packets)
    strings = "".join(strings)
    return re.split("[\r\n]+", strings)
