# coding: utf-8
from pyshark.packet.packet import Packet

from ncm.core import logger
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["snmp"], "version"):
        snmp_version = str(int(packet["snmp"].version)+1)
    elif hasattr(packet["snmp"], "msgversion"):
        snmp_version = packet["snmp"].msgversion
    else:
        snmp_version = "?"

    if hasattr(packet["snmp"], "community") \
            and (session["community_string"] is None or session["community_string"] != packet["snmp"].community):
        session["community_string"] = packet["snmp"].community
        logger.found("SNMPv" + snmp_version, "community string found: " + packet["snmp"].community)
        return Credentials(password=packet["snmp"].community)

    if hasattr(packet["snmp"], "msgusername") and packet["snmp"].msgusername != "msgUserName: " \
            and (session["username"] is None or session["username"] != packet["snmp"].msgusername):
        session["username"] = packet["snmp"].msgusername
        logger.found("SNMPv" + snmp_version, "username found: " + packet["snmp"].msgusername)
        return Credentials(packet["snmp"].msgusername)

    # Log stuff needed to break SNMPv3 ? https://www.usenix.org/system/files/conference/woot12/woot12-final14.pdf
