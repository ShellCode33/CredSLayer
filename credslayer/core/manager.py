# coding: utf-8
import os
import signal
import time
import traceback

import pyshark
from pyshark.capture.capture import TSharkCrashException, Capture
from pyshark.packet.packet import Packet

from credslayer.core import logger, extract, utils
from credslayer.core.session import SessionsManager, Session, stop_managed_sessions, SessionException
from credslayer.parsers import parsers, ntlmssp


class MalformedPacketException(Exception):
    pass


def clean_before_exit():
    stop_managed_sessions()

    if logger.OUTPUT_FILE:
        logger.OUTPUT_FILE.close()


def signal_handler(sig, frame):
    clean_before_exit()
    print("\nBye !")
    os._exit(0)  # Pretty hardcore I know, but pyshark is a real PITA when it comes to handling signals


def _process_packet(session: Session, packet: Packet, must_inspect_strings: bool):

    if len(packet.layers) > 3:  # == tshark parsed something else than ETH, IP, TCP

        for layer in packet.layers[3:]:
            layer_name = layer.layer_name

            if hasattr(layer, "_ws_malformed_expert"):
                raise MalformedPacketException("[{}] session contains malformed packet in layer '{}'".format(session, layer_name))

            # Not based on layer name, can be found in different layers
            if hasattr(layer, "nt_status") or (hasattr(layer, "ntlmssp_identifier") and layer.ntlmssp_identifier == "NTLMSSP"):
                session.protocol = layer_name.upper()
                ntlmssp.analyse(session, layer)

            # Analyse the layer with the appropriate parser
            if layer_name in parsers:
                session.protocol = layer_name.upper()
                parsers[layer_name].analyse(session, layer)

    if must_inspect_strings:
        strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
        emails_found = extract.extract_emails(strings)
        credit_cards_found = extract.extract_credit_cards(strings)

        for email in emails_found:
            logger.info(session, "Found email address: " + email)

        for credit_card in credit_cards_found:
            logger.info(session, "Credit card '{}' found: '{}'".format(credit_card.name, credit_card.number))


def _process_packets_from(packets_input: Capture, manager: SessionsManager, must_inspect_strings: bool):

    try:
        for packet in packets_input:
            try:
                session = manager.get_session_of(packet)
            # Not being able to retrieve a session from a packet means the packet is not supported
            except SessionException:
                continue

            try:
                _process_packet(session, packet, must_inspect_strings)

            except MalformedPacketException as e:
                logger.error(str(e) + ", CredSLayer will keep going")

            except Exception:
                traceback.print_exc()
                logger.error("An exception occurred but CredSLayer will keep going.")

    except TSharkCrashException:
        traceback.print_exc()
        logger.error("tshark crashed :(")
        clean_before_exit()


def process_pcap(filename: str, must_inspect_strings=False, tshark_filter=None, debug=False, decode_as=None) -> SessionsManager:

    logger.DEBUG_MODE = debug
    sessions_manager = SessionsManager()

    with pyshark.FileCapture(filename, display_filter=tshark_filter, decode_as=decode_as, debug=debug) as pcap:
        logger.info("Processing packets in '{}'".format(filename))

        start_time = time.time()

        _process_packets_from(pcap, sessions_manager, must_inspect_strings)

        remaining_credentials = sessions_manager.get_remaining_content()

        if remaining_credentials:
            logger.info("Interesting things have been found but the CredSLayer wasn't able validate them: ")
            # List things that haven't been reported (sometimes the success indicator has
            # not been captured and credentials stay in the session without being logged)
            for session, remaining in remaining_credentials:
                logger.info(session, str(remaining))

        logger.info("Processed in {0:.3f} seconds.".format(time.time() - start_time))

    return sessions_manager


def active_processing(interface: str, must_inspect_strings=False, tshark_filter=None, debug=False, decode_as=None, pcap_output=None):

    logger.DEBUG_MODE = debug

    sessions = SessionsManager(remove_outdated=True)

    signal.signal(signal.SIGINT, signal_handler)

    with pyshark.LiveCapture(interface=interface, bpf_filter=tshark_filter, debug=debug,
                             decode_as=decode_as, output_file=pcap_output) as live:

        logger.info("Listening on {}...".format(interface))
        _process_packets_from(live.sniff_continuously(), sessions, must_inspect_strings)
