# coding: utf-8

from scapy.plist import PacketList
from ncm.core import logger
from ncm.core.utils import CredentialsList


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("LDAP analysis...")

    return []
