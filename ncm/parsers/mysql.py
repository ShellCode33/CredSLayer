# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "server_greeting"):

        if hasattr(layer, "version"):
            logger.info("MySQL version: " + layer.version)

        if hasattr(layer, "salt"):
            session["salt"] = [layer.salt]

        if hasattr(layer, "salt2"):
            session["salt"].append(layer.salt2)

    if hasattr(layer, "client_auth_plugin"):
        logger.info("MySQL auth plugin: " + layer.client_auth_plugin)

    if hasattr(layer, "user"):
        session["username"] = layer.user
        session["hash"] = "".join(layer.passwd.split(":"))

    if hasattr(layer, "response_code"):
        response_code = int(layer.response_code, 16)

        if session["username"] and response_code == 0:

            for i in range(len(session["salt"])):
                logger.found("MySQL", "salt{} found: {}".format(i+1, session["salt"][i]))

            logger.found("MySQL", "credentials found: {} -- {}".format(session["username"], session["hash"]))
            return Credentials(session["username"], hash=session["hash"], salt=session["salt"])
