# coding: utf-8

from pyshark.packet.packet import Packet
from ncm.core import utils
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["pop"], "request_command"):
        command = packet["pop"].request_command

        if hasattr(packet["pop"], "request_parameter"):
            parameter = packet["pop"].request_parameter

            if command == "AUTH":
                # TODO : handle more types of auth
                if parameter == "PLAIN":
                    session["auth_process_plain"] = True

        elif session["auth_process_plain"]:
            session["username"], session["password"] = utils.parse_sasl_creds(command, "PLAIN")

    if session["username"] and hasattr(packet["pop"], "response_indicator"):
        indicator = packet["pop"].response_indicator

        if indicator == "+OK":
            sessions.remove(session)
            return Credentials(session["username"], session["password"])

        elif indicator == "-ERR":
            sessions.remove(session)
