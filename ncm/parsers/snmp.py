# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "version"):
        snmp_version = str(int(layer.version)+1)
    elif hasattr(layer, "msgversion"):
        snmp_version = layer.msgversion
    else:
        snmp_version = "?"

    if hasattr(layer, "community") \
            and (session["community_string"] is None or session["community_string"] != layer.community):
        session["community_string"] = layer.community
        logger.found("SNMPv" + snmp_version, "community string found: " + layer.community)
        return Credentials(password=layer.community)

    if hasattr(layer, "msgusername") and layer.msgusername != "msgUserName: " \
            and (session["username"] is None or session["username"] != layer.msgusername):
        session["username"] = layer.msgusername
        logger.found("SNMPv" + snmp_version, "username found: " + layer.msgusername)
        return Credentials(layer.msgusername)

    # Log stuff needed to break SNMPv3 ? https://www.usenix.org/system/files/conference/woot12/woot12-final14.pdf
