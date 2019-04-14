# coding: utf-8

from pyshark.packet.packet import Packet
from ncm.core import logger
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["mysql"], "server_greeting"):

        if hasattr(packet["mysql"], "version"):
            logger.info("MySQL version: " + packet["mysql"].version)

        if hasattr(packet["mysql"], "salt"):
            session["salt"] = [packet["mysql"].salt]

        if hasattr(packet["mysql"], "salt2"):
            session["salt"].append(packet["mysql"].salt2)

    if hasattr(packet["mysql"], "client_auth_plugin"):
        logger.info("MySQL auth plugin: " + packet["mysql"].client_auth_plugin)

    if hasattr(packet["mysql"], "user"):
        session["username"] = packet["mysql"].user
        session["hash"] = "".join(packet["mysql"].passwd.split(":"))

    if hasattr(packet["mysql"], "response_code"):
        response_code = int(packet["mysql"].response_code, 16)

        if session["username"] and response_code == 0:
            sessions.remove(session)

            for i in range(len(session["salt"])):
                logger.found("MySQL", "salt{} found: {}".format(i+1, session["salt"][i]))

            logger.found("MySQL", "credentials found: {} -- {}".format(session["username"], session["hash"]))
            return Credentials(session["username"], hash=session["hash"], salt=session["salt"])
