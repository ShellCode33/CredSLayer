# coding: utf-8
from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "name"):
        session["username"] = layer.name

    if hasattr(layer, "simple"):
        session["password"] = layer.simple
        session["auth_process"] = True

    if session["auth_process"] and hasattr(layer, "resultcode"):
        result_code = int(layer.resultcode)
        session["auth_process"] = False

        if result_code == 0:
            logger.found("LDAP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])
