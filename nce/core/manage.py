# coding: utf-8

from nce.core import logger
from scapy.all import rdpcap


def session_extractor(p):
    """Extract sessions from packets. Has been taken from here :
    https://github.com/secdev/scapy/blob/master/scapy/plist.py#L505

    By default A talking to B and B answering to A are 2 different sessions. We want them to be the same.
    We simply apply an alphabetic sort on IP:PORT
    """

    if 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
            ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"

            addr_fmt = (ip_src_fmt, ip_dst_fmt)

            if 'TCP' in p:
                fmt = "TCP {}:%r,TCP.sport% | {}:%r,TCP.dport%"
            elif 'UDP' in p:
                fmt = "UDP {}:%r,UDP.sport% | {}:%r,UDP.dport%"
            elif 'ICMP' in p:
                fmt = "ICMP {} | {} type=%r,ICMP.type% code=%r," \
                      "ICMP.code% id=%ICMP.id%"
            elif 'ICMPv6' in p:
                fmt = "ICMPv6 {} | {} type=%r,ICMPv6.type% " \
                      "code=%r,ICMPv6.code%"
            elif 'IPv6' in p:
                fmt = "IPv6 {} | {} nh=%IPv6.nh%"
            else:
                fmt = "IP {} | {} proto=%IP.proto%"
            return p.sprintf(fmt.format(*addr_fmt))
        elif 'ARP' in p:
            return p.sprintf("ARP %ARP.psrc% | %ARP.pdst%")
        else:
            return p.sprintf("Ethernet type=%04xr,Ether.type%")

    return "Other"

def process_pcap(filename):
    logger.info("Processing packets in '{}'".format(filename))
    pcap = rdpcap(filename)

    pcap = pcap.sessions()

    print(pcap)

    i = 0

    for pkt in pcap:
        #pkt.show()
        if hasattr(pkt, "load"):
            print(pkt.load)
            print("-"*30)
        i += 1

        if i == 45:
            break

def active_processing(interface):
    logger.info("Listening on {}...".format(interface))
