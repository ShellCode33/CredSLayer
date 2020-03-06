# coding: utf-8

from pyshark.packet.layer import Layer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "version"):
        session.protocol = "SNMPv" + str(int(layer.version)+1)
    elif hasattr(layer, "msgversion"):
        session.protocol = "SNMPv" + layer.msgversion
    else:
        session.protocol = "SNMPv?"

    if hasattr(layer, "community") \
            and (session["community_string"] is None or session["community_string"] != layer.community):
        current_creds.password = session["community_string"] = layer.community
        logger.found(session, "community string found: " + layer.community)
        return True

    if hasattr(layer, "msgusername") and layer.msgusername != "msgUserName: " \
            and (session["username"] is None or session["username"] != layer.msgusername):
        current_creds.username = session["username"] = layer.msgusername
        logger.found(session, "username found: " + layer.msgusername)
        return True

    # Log stuff needed to break SNMPv3 ? https://www.usenix.org/system/files/conference/woot12/woot12-final14.pdf

    return False
