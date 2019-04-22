# coding: utf-8
import signal
import time
import traceback

import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.capture import TSharkCrashException
from csl.core import logger, extract, utils
from csl.core.session import SessionList
from csl.parsers import parsers, ntlmssp

_sessions = None


def signal_handler(sig, frame):

    if _sessions is not None:
        _sessions.__del__()

    print('Bye !')


def _process_packet(packet: Packet, must_inspect_strings):

    # We only support tcp & udp packets for now
    if "tcp" not in packet and "udp" not in packet:
        return

    session = _sessions.get_session_of(packet)

    if len(packet.layers) > 3:  # == tshark parsed something else than ETH, IP, TCP

        for layer in packet.layers[3:]:
            layer_name = layer.layer_name

            # Not based on layer name, can be found in different layers
            if hasattr(layer, "nt_status") or (hasattr(layer, "ntlmssp_identifier") and layer.ntlmssp_identifier == "NTLMSSP"):
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

    if must_inspect_strings:
        strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
        emails_found = extract.extract_emails(strings)
        credit_cards_found = extract.extract_credit_cards(strings)

        for email in emails_found:
            logger.info(session, "Found email address: " + email)

        for credit_card in credit_cards_found:
            logger.info(session, "Credit card '{}' found: '{}'".format(credit_card.name, credit_card.number))


def process_pcap(filename: str, must_inspect_strings=False, tshark_filter=None, debug=False) -> SessionList:

    global _sessions

    logger.DEBUG_MODE = debug
    _sessions = SessionList()

    pcap = pyshark.FileCapture(filename, display_filter=tshark_filter)
    logger.info("Processing packets in '{}'".format(filename))

    if debug:
        pcap.set_debug()

    start_time = time.time()

    for packet in pcap:
        try:
            _process_packet(packet, must_inspect_strings)
        except Exception as e:
            logger.error("An exception occurred when trying to process {} : {}".format(repr(packet), repr(e)))
            logger.info("Resuming analysis...")

    _sessions.process_sessions_remaining_content()

    logger.info("Processed in {0:.3f} seconds.".format(time.time() - start_time))
    pcap.close()
    return _sessions


def active_processing(interface: str, must_inspect_strings=False, tshark_filter=None, debug=False):

    global _sessions

    logger.DEBUG_MODE = debug
    _sessions = SessionList()

    _sessions.manage_outdated_sessions()
    signal.signal(signal.SIGINT, signal_handler)

    live = pyshark.LiveCapture(interface=interface, bpf_filter=tshark_filter)
    logger.info("Listening on {}...".format(interface))

    if debug:
        live.set_debug()

    try:
        for packet in live.sniff_continuously():
            try:
                _process_packet(packet, must_inspect_strings)
            except Exception as e:
                logger.error("An exception occurred when trying to process {} : {}".format(repr(packet), repr(e)))
                logger.info("Resuming analysis...")

    except TSharkCrashException:
        logger.error("tshark crashed :( Please report the following error :")
        traceback.print_exc()
        signal_handler(None, None)
