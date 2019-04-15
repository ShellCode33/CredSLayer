# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "request_command"):
        command = layer.request_command

        if command == "LOGIN":
            tokens = layer.request.split('"')
            session["username"] = tokens[1]
            session["password"] = tokens[3]

    elif hasattr(layer, "response_command"):
        command = layer.response_command

        if command == "LOGIN":
            status = layer.response_status

            if status == "OK":
                logger.found("IMAP", "credentials found: {} -- {}".format(session["username"], session["password"]))
                return Credentials(session["username"], session["password"])
            elif status == "NO" or status == "BAD":
                session["username"] = session["password"] = None
