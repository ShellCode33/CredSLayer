# coding: utf-8

import signal
import time

import pyshark
from pyshark.packet.packet import Packet

from ncm.core import logger, extract, utils
from ncm.core.session import SessionList
from ncm.parsers import parsers, ntlmssp

string_inspection = None
sessions = SessionList()


def signal_handler(sig, frame):
        sessions.__del__()
        print('Bye !')
        exit(0)


def _process_packet(packet: Packet):

    # We only support tcp & udp packets for now
    if "tcp" not in packet and "udp" not in packet:
        return

    if string_inspection:
        strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
        emails_found = extract.extract_emails(strings)
        credit_cards_found = extract.extract_credit_cards(strings)

        for email in emails_found:
            logger.info("Found email address: " + email)

        for credit_card in credit_cards_found:
            logger.info("Credit card '{}' found: '{}'".format(credit_card.name, credit_card.number))

    if len(packet.layers) > 3:  # == tshark parsed something else than ETH, IP, TCP

        session = sessions.get_session_of(packet)

        for layer in packet.layers[3:]:
            layer_name = layer.layer_name

            if hasattr(layer, "ntlmssp_identifier") and layer.ntlmssp_identifier == "NTLMSSP":
                if ntlmssp.analyse(session, layer):
                    sessions.remove(session)

            elif layer_name in parsers:
                parsers[layer_name].analyse(session, layer)


def process_pcap(filename: str):

    global string_inspection

    if string_inspection is None:
        string_inspection = True

    pcap = pyshark.FileCapture(filename)
    logger.debug("Processing packets in '{}'".format(filename))

    start_time = time.time()

    # TODO: at given time (every INACTIVE_SESSION_DELAY seconds ?) clean inactive sessions, log uncomplete credentials ?

    for packet in pcap:
        _process_packet(packet)

    logger.debug("Processed in {0:.3f} seconds.".format(time.time() - start_time))


def active_processing(interface: str):

    global string_inspection

    if string_inspection is None:
        string_inspection = False

    signal.signal(signal.SIGINT, signal_handler)
    sessions.manage_outdated_sessions()

    logger.info("Listening on {}...".format(interface))
    live = pyshark.LiveCapture(interface=interface)
    live.apply_on_packets(_process_packet)
