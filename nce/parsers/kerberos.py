# coding: utf-8

from scapy.plist import PacketList
from nce.core import logger
from nce.core.utils import CredentialsList


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("Kerberos analysis...")

    return []
