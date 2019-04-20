# coding: utf-8

from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "server_greeting"):

        if hasattr(layer, "version"):
            logger.info(session, "MySQL version: " + layer.version)

        if hasattr(layer, "salt"):
            current_creds.context["salt"] = layer.salt

        if hasattr(layer, "salt2"):
            current_creds.context["salt2"] = layer.salt2

    if hasattr(layer, "client_auth_plugin"):
        logger.info(session, "MySQL auth plugin: " + layer.client_auth_plugin)

    if hasattr(layer, "user"):
        current_creds.username = layer.user
        current_creds.hash = "".join(layer.passwd.split(":"))

    if hasattr(layer, "response_code"):
        response_code = int(layer.response_code, 16)

        if current_creds.username and response_code == 0:

            for item in current_creds.context:
                logger.found(session, "{} found: {}".format(item, current_creds.context[item]))

            logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.hash))
            return True

    return False
