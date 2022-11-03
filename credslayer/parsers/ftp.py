# coding: utf-8

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):

    current_creds = session.credentials_being_built

    if hasattr(layer, "response_code"):
        code = int(layer.response_code)

        if code == 230 and current_creds.username:
            logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
            session.validate_credentials()

        elif code == 430:
            session.invalidate_credentials_and_clear_session()

    elif hasattr(layer, "request_command"):
        command = layer.request_command

        if command == "USER":
            current_creds.username = layer.request_arg

        elif command == "PASS":
            current_creds.password = layer.request_arg
