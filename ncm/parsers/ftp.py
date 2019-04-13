# coding: utf-8

from pyshark.packet.packet import Packet
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["ftp"], "response_code"):
        code = int(packet["ftp"].response_code)

        if code == 230 and session["username"] and session["password"]:
            sessions.remove(session)
            return Credentials(session["username"], session["password"])

        elif code == 430:
            sessions.remove(session)
            session["username"] = session["password"] = None

    elif hasattr(packet["ftp"], "request_command"):
        command = packet["ftp"].request_command

        if command == "USER":
            session["username"] = packet["ftp"].request_arg

        elif command == "PASS":
            session["password"] = packet["ftp"].request_arg
