# coding: utf-8

from collections import namedtuple
from typing import List

from scapy.packet import Packet
from scapy.plist import PacketList


Credentials = namedtuple('Credentials', ['username', 'password'])
Credentials.__new__.__defaults__ = (None,) * len(Credentials._fields)  # Create username and password default values
CredentialsList = List[Credentials]


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

    src = "{}:{}".format(pkt[pkt_type].src, pkt[pkt_type].sport)
    dst = "{}:{}".format(pkt[pkt_type].dst, pkt[pkt_type].dport)

    if src < dst:
        return src + " | " + dst
    else:
        return dst + " | " + src


def extract_strings_from(packets: PacketList) -> list:
    """Build a list of strings from packets' payload.
    """

    strings = []

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        try:
            string = packet.load.decode()
            strings.append(string)
        except UnicodeDecodeError:
            continue

    return strings
