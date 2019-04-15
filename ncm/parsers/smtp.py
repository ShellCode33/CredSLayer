# coding: utf-8

from base64 import b64decode

from pyshark.packet.layer import Layer

from ncm.core import utils, logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

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
            session["username"] = b64decode(username).decode()

        elif hasattr(layer, "auth_password"):
            password = layer.auth_password
            session["password"] = b64decode(password).decode()
            session["auth_process_login"] = False

    elif session["auth_process_plain"]:
        if hasattr(layer, "auth_username"):
            b64_auth = layer.auth_username
            session["username"], session["password"] = utils.parse_sasl_creds(b64_auth, "PLAIN")
            session["auth_process_plain"] = False

    if hasattr(layer, "response_code"):
        response_code = int(layer.response_code)

        if response_code == 235:
            logger.found("SMTP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])
