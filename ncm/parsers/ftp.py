# coding: utf-8
from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "response_code"):
        code = int(layer.response_code)

        if code == 230 and session["username"] and session["password"]:
            logger.found("FTP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])

        elif code == 430:
            session["username"] = session["password"] = None

    elif hasattr(layer, "request_command"):
        command = layer.request_command

        if command == "USER":
            session["username"] = layer.request_arg

        elif command == "PASS":
            session["password"] = layer.request_arg
