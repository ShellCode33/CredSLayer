# coding: utf-8
import signal
import time
import traceback

import pyshark
from pyshark.capture.capture import TSharkCrashException
from pyshark.packet.packet import Packet

from credslayer.core import logger, extract, utils
from credslayer.core.session import SessionList
from credslayer.parsers import parsers, ntlmssp

_sessions = None


class MalformedPacketException(Exception):
    pass


def clean_before_exit():
    if _sessions is not None:
        _sessions.__del__()

    if logger.OUTPUT_FILE:
        logger.OUTPUT_FILE.close()


def signal_handler(sig, frame):
    clean_before_exit()
    print('Bye !')


def _process_packet(packet: Packet, must_inspect_strings: bool):

    # We only support tcp & udp packets for now
    if "tcp" not in packet and "udp" not in packet:
        return

    session = _sessions.get_session_of(packet)

    if len(packet.layers) > 3:  # == tshark parsed something else than ETH, IP, TCP

        for layer in packet.layers[3:]:
            layer_name = layer.layer_name

            if hasattr(layer, "_ws_malformed_expert"):
                raise MalformedPacketException("[{}] session contains malformed packet in layer '{}'".format(session, layer_name))

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


def process_pcap(filename: str, must_inspect_strings=False, tshark_filter=None, debug=False, decode_as=None) -> SessionList:

    global _sessions

    logger.DEBUG_MODE = debug
    _sessions = SessionList()

    pcap = pyshark.FileCapture(filename, display_filter=tshark_filter, decode_as=decode_as)
    logger.info("Processing packets in '{}'".format(filename))

    if debug:
        pcap.set_debug()

    start_time = time.time()

    for packet in pcap:
        try:
            _process_packet(packet, must_inspect_strings)

        except MalformedPacketException as e:
            logger.error(str(e) + ", CredSLayer will keep going")

        except Exception:
            traceback.print_exc()
            logger.error("An exception occurred but CredSLayer will keep going.")

    _sessions.process_sessions_remaining_content()

    logger.info("Processed in {0:.3f} seconds.".format(time.time() - start_time))
    pcap.close()
    return _sessions


def active_processing(interface: str, must_inspect_strings=False, tshark_filter=None, debug=False, decode_as=None, pcap_output=None):

    global _sessions

    logger.DEBUG_MODE = debug
    _sessions = SessionList()

    _sessions.manage_outdated_sessions()
    signal.signal(signal.SIGINT, signal_handler)

    live = pyshark.LiveCapture(interface=interface, bpf_filter=tshark_filter, decode_as=decode_as, output_file=pcap_output)
    logger.info("Listening on {}...".format(interface))

    if debug:
        live.set_debug()

    try:
        for packet in live.sniff_continuously():
            try:
                _process_packet(packet, must_inspect_strings)

            except MalformedPacketException as e:
                logger.error(str(e) + ", CredSLayer will keep going")

            except Exception:
                traceback.print_exc()
                logger.error("An exception occurred but CredSLayer will keep going.")

    except TSharkCrashException:
        logger.error("tshark crashed :( Please report the following error :")
        traceback.print_exc()
        clean_before_exit()
