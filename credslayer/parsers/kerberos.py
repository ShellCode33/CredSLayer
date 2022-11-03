# coding: utf-8

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer) -> bool:
    logger.debug("Kerberos analysis...")

    return False
