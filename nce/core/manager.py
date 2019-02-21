# coding: utf-8

from nce.core import logger, utils
from scapy.all import *
from nce.parsers import parsers


def process_pcap(filename):
    logger.debug("Processing packets in '{}'".format(filename))
    sessions = rdpcap(filename).sessions(utils.session_extractor)

    if "WeDontCare" in sessions:
        del sessions["WeDontCare"]

    logger.info("Identified {} session(s)".format(len(sessions)))

    for session in sessions:
        logger.info("Session: {}".format(session))
        packets = sessions[session]

        for parser in parsers:
            credentials = parser.analyse(packets)

            if len(credentials) > 0:
                module_name = parser.__name__.split(".")[-1].upper()

                for cred in credentials:
                    logger.found(module_name, *cred)

                break  # Credentials have been found in this session, we can skip the other parsers


def active_processing(interface):
    logger.info("Listening on {}...".format(interface))
