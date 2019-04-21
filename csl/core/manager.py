# coding: utf-8
import signal
import time

import pyshark
from pyshark.packet.packet import Packet

from csl.core import logger, extract, utils
from csl.core.session import SessionList
from csl.parsers import parsers, ntlmssp

string_inspection = None
_sessions = None


def signal_handler(sig, frame):
    if _sessions:
        _sessions.__del__()

    print('Bye !')
    exit(0)


def _process_packet(packet: Packet):

    # We only support tcp & udp packets for now
    if "tcp" not in packet and "udp" not in packet:
        return

    session = _sessions.get_session_of(packet)

    if len(packet.layers) > 3:  # == tshark parsed something else than ETH, IP, TCP

        for layer in packet.layers[3:]:
            layer_name = layer.layer_name

            are_credentials_valid = False

            # Not based on layer name, can be found in different layers
            if hasattr(layer, "ntlmssp_identifier") and layer.ntlmssp_identifier == "NTLMSSP":
                session.protocol = layer_name.upper()
                are_credentials_valid = ntlmssp.analyse(session, layer)

                if are_credentials_valid:
                    session.validate_credentials()

            # Analyse the layer with the appropriate parser
            if layer_name in parsers:
                session.protocol = layer_name.upper()
                are_credentials_valid = parsers[layer_name].analyse(session, layer)

                if are_credentials_valid:
                    session.validate_credentials()

    if string_inspection:
        strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
        emails_found = extract.extract_emails(strings)
        credit_cards_found = extract.extract_credit_cards(strings)

        for email in emails_found:
            logger.info(session, "Found email address: " + email)

        for credit_card in credit_cards_found:
            logger.info(session, "Credit card '{}' found: '{}'".format(credit_card.name, credit_card.number))


def process_pcap(filename: str) -> SessionList:

    global string_inspection, _sessions

    _sessions = SessionList()

    if string_inspection is None:
        string_inspection = True

    pcap = pyshark.FileCapture(filename)
    logger.debug("Processing packets in '{}'".format(filename))

    start_time = time.time()

    for packet in pcap:
        _process_packet(packet)

    _sessions.process_sessions_remaining_content()

    logger.debug("Processed in {0:.3f} seconds.".format(time.time() - start_time))
    return _sessions


def active_processing(interface: str):

    global string_inspection, _sessions

    _sessions = SessionList()

    if string_inspection is None:
        string_inspection = False

    signal.signal(signal.SIGINT, signal_handler)
    _sessions.manage_outdated_sessions()

    logger.info("Listening on {}...".format(interface))
    live = pyshark.LiveCapture(interface=interface)
    live.apply_on_packets(_process_packet)
