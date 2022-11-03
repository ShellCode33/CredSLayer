# coding: utf-8
from pyshark.packet.layers.base import BaseLayer

from credslayer.core import utils, logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):

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
            session.validate_credentials()

        elif indicator == "-ERR":
            session.invalidate_credentials_and_clear_session()
