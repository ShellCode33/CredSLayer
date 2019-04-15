# coding: utf-8
from pyshark.packet.layer import Layer

from ncm.core import utils, logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

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
            session["username"], session["password"] = utils.parse_sasl_creds(command, "PLAIN")

    if session["username"] and hasattr(layer, "response_indicator"):
        indicator = layer.response_indicator

        if indicator == "+OK":
            logger.found("POP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])

        elif indicator == "-ERR":
            session["username"] = session["password"] = None
