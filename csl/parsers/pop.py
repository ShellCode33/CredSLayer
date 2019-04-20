# coding: utf-8
from pyshark.packet.layer import Layer

from csl.core import utils, logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "request_command"):
        command = layer.request_command

        if hasattr(layer, "request_parameter"):
            parameter = layer.request_parameter

            if command == "AUTH":
                # TODO : handle more types of auth
                if parameter == "PLAIN":
                    session["auth_process_plain"] = True

        elif session["auth_process_plain"]:
            session["auth_process_plain"] = False
            current_creds.username, current_creds.password = utils.parse_sasl_creds(command, "PLAIN")

    if current_creds.username and hasattr(layer, "response_indicator"):
        indicator = layer.response_indicator

        if indicator == "+OK":
            logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
            return True

        elif indicator == "-ERR":
            session.invalidate_credentials_and_clear_session()

    return False
