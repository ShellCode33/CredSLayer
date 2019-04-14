# coding: utf-8

from base64 import b64decode
from pyshark.packet.packet import Packet
from ncm.core import utils, logger
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["smtp"], "req_command"):
        command = packet["smtp"].req_command

        if hasattr(packet["smtp"], "req_parameter"):
            parameter = packet["smtp"].req_parameter

            if command == "AUTH":
                # TODO : handle more types of auth
                if parameter.startswith("LOGIN"):
                    session["auth_process_login"] = True
                elif parameter.startswith("PLAIN"):  # TODO: not tested, find a pcap
                    session["auth_process_plain"] = True

    if session["auth_process_login"]:
        if hasattr(packet["smtp"], "auth_username"):
            username = packet["smtp"].auth_username
            session["username"] = b64decode(username).decode()

        elif hasattr(packet["smtp"], "auth_password"):
            password = packet["smtp"].auth_password
            session["password"] = b64decode(password).decode()

    elif session["auth_process_plain"]:
        if hasattr(packet["smtp"], "auth_username"):
            b64_auth = packet["smtp"].auth_username
            session["username"], session["password"] = utils.parse_sasl_creds(b64_auth, "PLAIN")

    if hasattr(packet["smtp"], "response_code"):
        response_code = int(packet["smtp"].response_code)

        if response_code == 235:
            sessions.remove(session)
            logger.found("SMTP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])

        # According to the RFC, the server could return something else, but most of the times it will be 535
        elif response_code == 535:
            sessions.remove(session)
