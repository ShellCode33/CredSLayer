# coding: utf-8

from pyshark.packet.layer import Layer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: Layer):

    current_creds = session.credentials_being_built

    if hasattr(layer, "request_command"):
        command = layer.request_command

        if command == "LOGIN":
            tokens = layer.request.split('"')
            current_creds.username = tokens[1]
            current_creds.password = tokens[3]

    # Due to an incompatibility with "old" tshark versions, we cannot use response_command :(
    elif hasattr(layer, "response"):
        command = layer.response

        if " LOGIN " in command:
            status = layer.response_status

            if status == "OK":
                logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                session.validate_credentials()

            elif status == "NO" or status == "BAD":
                session.invalidate_credentials_and_clear_session()
