# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:
    logger.debug("Kerberos analysis...")

    return False
