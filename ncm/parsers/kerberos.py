# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:
    logger.debug("Kerberos analysis...")

    return []
