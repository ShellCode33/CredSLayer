# coding: utf-8

from scapy.plist import PacketList
from ncm.core import logger
from ncm.core.utils import CredentialsList


def _mysql_analyse(packets: PacketList) -> CredentialsList:
    return []


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("SQL analysis...")

    return []
