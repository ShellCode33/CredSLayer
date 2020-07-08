# coding: utf-8

from base64 import b64decode

from pyshark.packet.layer import Layer

from credslayer.core import utils, logger
from credslayer.core.session import Session


def analyse(session: Session, layer: Layer):

    current_creds = session.credentials_being_built

    if hasattr(layer, "req_command"):
        command = layer.req_command

        if hasattr(layer, "req_parameter"):
            parameter = layer.req_parameter

            if command == "AUTH":
                # TODO : handle more types of auth
                if parameter.startswith("LOGIN"):
                    session["auth_process_login"] = True
                elif parameter.startswith("PLAIN"):  # TODO: not tested, find a pcap
                    session["auth_process_plain"] = True

    if session["auth_process_login"]:
        if hasattr(layer, "auth_username"):
            username = layer.auth_username
            current_creds.username = b64decode(username).decode()

        elif hasattr(layer, "auth_password"):
            password = layer.auth_password
            current_creds.password = b64decode(password).decode()
            session["auth_process_login"] = False

    elif session["auth_process_plain"]:
        if hasattr(layer, "auth_username"):
            b64_auth = layer.auth_username
            current_creds.username, current_creds.password = utils.parse_sasl_creds(b64_auth, "PLAIN")
            session["auth_process_plain"] = False

    if hasattr(layer, "response_code"):
        response_code = int(layer.response_code)

        if response_code == 235:
            logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
            session.validate_credentials()
