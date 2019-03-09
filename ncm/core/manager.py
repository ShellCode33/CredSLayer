# coding: utf-8

from ncm.core import logger, utils, extract
from scapy.all import *
from ncm.parsers import parsers


def process_pcap(filename: str):

    start_time = time.time()
    pcap = rdpcap(filename)
    logger.debug("Processing packets in '{}'".format(filename))
    sessions = pcap.sessions(utils.session_extractor)

    if "WeDontCare" in sessions:
        del sessions["WeDontCare"]

    logger.info("Identified {} session(s)".format(len(sessions)))

    for session in sessions:
        logger.info("Session: {}".format(session))
        packets = sessions[session]

        emails_found = extract.extract_emails(packets)
        credit_cards_found = extract.extract_credit_cards(packets)

        for email in emails_found:
            logger.info("Found email address: " + email)

        for credit_card in credit_cards_found:
            logger.info("Credit card '{}' found: '{}'".format(credit_card.name, credit_card.number))

        for parser in parsers:
            credentials = parser.analyse(packets)

            if len(credentials) > 0:
                module_name = parser.__name__.split(".")[-1].upper()

                for cred in credentials:
                    logger.found(module_name, cred)

                break  # Credentials have been found in this session, we can skip the other parsers

    logger.info("Processed in {0:.3f} seconds.".format(time.time()-start_time))


def active_processing(interface: str):
    logger.info("Listening on {}...".format(interface))
