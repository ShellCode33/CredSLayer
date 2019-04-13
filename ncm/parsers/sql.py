# coding: utf-8
from pyshark.packet.packet import Packet
from scapy.plist import PacketList
from ncm.core import logger
from ncm.core.utils import Credentials


def _mysql_analyse(packet: Packet) -> Credentials:
    return []


def analyse(packet: Packet) -> Credentials:
    logger.debug("SQL analysis...")

    return []
