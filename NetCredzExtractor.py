#!/usr/bin/python3
# coding: utf-8

from nce.core import manager
import argcomplete
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Helps you find credentials and other interesting stuff in network captures')
    parser.add_argument("pcapfiles",
                        nargs='+',
                        help='pcap files you want to analyse.')
    parser.add_argument('-l', '--listen',
                        help='start active processing on specified interface',
                        metavar='INTERFACE')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    for pcap in args.pcapfiles:
        manager.process_pcap(pcap)
