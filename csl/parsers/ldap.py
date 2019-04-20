# coding: utf-8
from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "name"):
        current_creds.username = layer.name

    if hasattr(layer, "simple"):
        current_creds.password = layer.simple
        session["auth_process"] = True

    if session["auth_process"] and hasattr(layer, "resultcode"):
        result_code = int(layer.resultcode)
        session["auth_process"] = False

        if result_code == 0:
            logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
            return True

    return False
