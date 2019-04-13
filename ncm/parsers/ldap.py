# coding: utf-8

from pyshark.packet.packet import Packet
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["ldap"], "name"):
        session["username"] = packet["ldap"].name

    if hasattr(packet["ldap"], "simple"):
        session["password"] = packet["ldap"].simple
        session["auth_process"] = True

    if session["auth_process"] and hasattr(packet["ldap"], "resultcode"):
        result_code = int(packet["ldap"].resultcode)
        sessions.remove(session)

        if result_code == 0:
            return Credentials(session["username"], session["password"])
