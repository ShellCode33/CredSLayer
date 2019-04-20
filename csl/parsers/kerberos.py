# coding: utf-8

from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:
    logger.debug("Kerberos analysis...")

    return False
