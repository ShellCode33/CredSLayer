# coding: utf-8

from scapy.plist import PacketList
from nce.core import logger
from nce.core.utils import CredentialsList


def _mysql_analyse(packets: PacketList) -> CredentialsList:
    return []


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("SQL analysis...")

    return []
