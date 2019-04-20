# coding: utf-8

from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "request_command"):
        command = layer.request_command

        if command == "LOGIN":
            tokens = layer.request.split('"')
            current_creds.username = tokens[1]
            current_creds.password = tokens[3]

    elif hasattr(layer, "response_command"):
        command = layer.response_command

        if command == "LOGIN":
            status = layer.response_status

            if status == "OK":
                logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                return True
            elif status == "NO" or status == "BAD":
                session.invalidate_credentials_and_clear_session()

    return False
