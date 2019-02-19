# coding: utf-8

from nce.core import logger
from scapy.all import *
from nce.parsers import parsers


def session_extractor(pkt):
    """Extract sessions from packets.

    By default A talking to B and B answering to A are 2 different sessions. We want them to be the same.
    We simply apply an alphabetic sort on IP:PORT to determine which one will go first in the string.
    """

    if "IP" in pkt:
        pkt_type = "IP"
    elif "IPv6" in pkt:
        pkt_type = "IPv6"
    else:
        return "WeDontCare"

    src = "{}:{}".format(pkt[pkt_type].src, pkt[pkt_type].sport)
    dst = "{}:{}".format(pkt[pkt_type].dst, pkt[pkt_type].dport)

    if src < dst:
        return src + " | " + dst
    else:
        return dst + " | " + src


def process_pcap(filename):
    logger.debug("Processing packets in '{}'".format(filename))
    sessions = rdpcap(filename).sessions(session_extractor)

    if "WeDontCare" in sessions:
        del sessions["WeDontCare"]

    logger.debug("Identified {} session(s) :".format(len(sessions)))

    for session in sessions:
        logger.debug("Session: {}".format(session))
        packets = sessions[session]

        for parser in parsers:
            credentials = parser.parse(packets)

            if credentials != (None, None):

                if credentials[0] is None:
                    logger.info("No username has been found (None)")

                elif credentials[1] is None:
                    logger.info("No password has been found (None)")

                logger.info("The following credentials have been found: '{}' '{}'".format(*credentials))


def active_processing(interface):
    logger.info("Listening on {}...".format(interface))


if __name__ == "__main__":
    process_pcap("tests/samples/telnet-cooked.pcap")
