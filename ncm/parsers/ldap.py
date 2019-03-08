# coding: utf-8

from scapy.plist import PacketList
from ncm.core import logger, utils
from ncm.core.utils import CredentialsList, Credentials
import re

LDAP_BIND_REQUEST_REGEX = re.compile(b"\x30.\x02\x01(?P<message_id>.)\x60.\x02\x01"
                                     b"(?P<ldap_version>[\x01\x02\x03])\x04(?P<DN_size>.)(?P<DN>.*)\x80"
                                     b"(?P<pass_size>.)(?P<password>.*)", re.DOTALL)


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("LDAP analysis...")

    all_credentials = []

    username = password = message_id = None

    for packet in packets:
        if hasattr(packet, "load"):

            if message_id is not None:
                # If this regex matches, it means the server returned successful authentication
                if re.search(b"\x30.*\x02\x01" + message_id + b"\x61.*\x0a\x01\x00", packet.load):
                    all_credentials.append(Credentials(username, password))
                    username = password = message_id = None

            result = LDAP_BIND_REQUEST_REGEX.search(packet.load)

            if result:
                username = result.group("DN").decode()
                password = result.group("password").decode()
                message_id = result.group("message_id")

    return all_credentials
