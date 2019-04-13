# coding: utf-8
from pyshark.packet.packet import Packet

from ncm.core import logger
from ncm.core.utils import Credentials


def analyse(packet: Packet) -> Credentials:
    logger.debug("Kerberos analysis...")

    return []
