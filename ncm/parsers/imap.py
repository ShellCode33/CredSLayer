# coding: utf-8

from pyshark.packet.packet import Packet

from ncm.core import logger
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:
    session = sessions.get_session_of(packet)

    if hasattr(packet["imap"], "request_command"):
        command = packet["imap"].request_command

        if command == "LOGIN":
            tokens = packet["imap"].request.split('"')
            session["username"] = tokens[1]
            session["password"] = tokens[3]

    elif hasattr(packet["imap"], "response_command"):
        command = packet["imap"].response_command

        if command == "LOGIN":
            status = packet["imap"].response_status

            if status == "OK":
                sessions.remove(session)
                logger.found("IMAP", "credentials found: {} -- {}".format(session["username"], session["password"]))
                return Credentials(session["username"], session["password"])
            elif status == "NO" or status == "BAD":
                sessions.remove(session)
