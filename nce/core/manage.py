# coding: utf-8

from nce.core import logger
from scapy.all import *


def session_extractor(pkt):
    """Extract sessions from packets. Has been taken from here :
    https://github.com/secdev/scapy/blob/master/scapy/plist.py#L505

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
    logger.info("Processing packets in '{}'".format(filename))
    pcap = rdpcap(filename)

    pcap = pcap.sessions(session_extractor)

    print(pcap)

    i = 0

    for pkt in pcap:
        # pkt.show()
        if hasattr(pkt, "load"):
            print(pkt.load)
            print("-" * 30)
        i += 1

        if i == 45:
            break


def active_processing(interface):
    logger.info("Listening on {}...".format(interface))


if __name__ == "__main__":
    process_pcap("tests/samples/telnet-cooked.pcap")
