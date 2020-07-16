# coding: utf-8
import os
import signal
import time
import traceback

import pyshark
from pyshark.capture.capture import TSharkCrashException, Capture
from pyshark.packet.packet import Packet
from pyshark.tshark.tshark import TSharkNotFoundException

from credslayer.core import logger, extract, utils
from credslayer.core.session import SessionsManager, Session, stop_managed_sessions, SessionException
from credslayer.parsers import parsers, ntlmssp


class MalformedPacketException(Exception):
    """
    This exception is raised when a malformed packet has been detected, therefore it cannot be analysed,
    or at least not by CredSLayer.
    """
    pass


def clean_before_exit():
    """
    Makes sure resources are closed properly before exiting CredSLayer.
    """
    stop_managed_sessions()

    if logger.OUTPUT_FILE:
        logger.OUTPUT_FILE.close()


def signal_handler(sig, frame):
    """
    Handles the SIGINT signal (received when hitting CTRL+C).
    """
    clean_before_exit()
    print("\nBye !")
    os._exit(0)  # Pretty hardcore I know, but pyshark is a real PITA when it comes to handling signals


def _process_packet(session: Session, packet: Packet, must_inspect_strings: bool):
    """
    Processes a single packet within its context thanks to the `Session` instance.

    Parameters
    ----------
    session : Session
        The session the packet belongs to.

    packet : Packet
        To packet to be analysed.

    must_inspect_strings : bool
        Whether strings in the packet should be inspected or not. Can be pretty heavy on the CPU.
    """

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


def _process_packets_from(packets_input: Capture, manager: SessionsManager, must_inspect_strings: bool = False):
    """
    Loops over available packets, retrieves its session and handles potential exceptions.

    Parameters
    ----------
    packets_input : Capture
        Iterator containing packets, can come from a pcap or a live capture.

    manager : SessionsManager
        The manager to be used to process the given packets.

    must_inspect_strings : bool
        Whether strings in the packet should be inspected or not. Can be pretty heavy on the CPU.
    """

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

    except TSharkNotFoundException:
        logger.error("tshark not found, have you installed it ?")
        clean_before_exit()


def process_pcap(filename: str, must_inspect_strings=False, tshark_filter=None, debug=False,
                 decode_as=None, creds_found_callback=None) -> SessionsManager:
    """
    Initialize the processing of a pcap file and retrieve results of the analysis.
    This is one of the main entry points most people will want to use.

    Parameters
    ----------
    filename : str
        Path to the pcap to process.

    must_inspect_strings : bool
        Whether strings in the packet should be inspected or not. Can be pretty heavy on the CPU.

    tshark_filter : string
        Display filter passed to tshark. Example : "ip.src == 192.168.1.42 or ip.dst == 192.168.1.42"
        See : https://wiki.wireshark.org/DisplayFilters

    debug : bool
        Toggle the debug mode of tshark, useful to track down bugs.

    decode_as : Dict[str, str]
        Associate a protocol to a port so that tshark processes packets correctly.

    creds_found_callback : Callable[[Credentials], None]
        The function to call every time new credentials are found. Credentials are passed as parameter.

    Returns
    -------
    A `SessionsManager` instance which gives to ability to the user of that function to retrieve
    what has been found in the pcap.
    """

    logger.DEBUG_MODE = debug
    sessions_manager = SessionsManager()
    Session.creds_found_callback = creds_found_callback

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


def active_processing(interface: str, must_inspect_strings=False, tshark_filter=None, debug=False, decode_as=None,
                      pcap_output=None, creds_found_callback=None):
    """
    Initialize packets capturing on a given interface file.
    This is one of the main entry points most people will want to use.

    Parameters
    ----------
    interface : str
        The network interface to listen to.

    must_inspect_strings : bool
        Whether strings in the packet should be inspected or not. Can be pretty heavy on the CPU.

    tshark_filter : string
        Capture filter passed to tshark. Example : "host 192.168.1.42"
        See : https://wiki.wireshark.org/CaptureFilters

    debug : bool
        Toggle the debug mode of tshark, useful to track down bugs.

    decode_as : Dict[str, str]
        Associate a protocol to a port so that tshark processes packets correctly.

    pcap_output : str
        Captured packets will be output to that file path.

    creds_found_callback : Callable[[Credentials], None]
        The function to call every time new credentials are found. Credentials are passed as parameter.
    """

    logger.DEBUG_MODE = debug

    sessions = SessionsManager(remove_outdated=True)
    Session.creds_found_callback = creds_found_callback

    signal.signal(signal.SIGINT, signal_handler)

    with pyshark.LiveCapture(interface=interface, bpf_filter=tshark_filter, debug=debug,
                             decode_as=decode_as, output_file=pcap_output) as live:

        logger.info("Listening on {}...".format(interface))
        _process_packets_from(live.sniff_continuously(), sessions, must_inspect_strings)
