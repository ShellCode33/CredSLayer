#!/usr/bin/python3
# coding: utf-8

from nce.core import manager
import argcomplete
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='NetCredzExtractor')
    parser.add_argument("files",
                        nargs='*',
                        help='Pcap files you want to analyse.')
    parser.add_argument('-l', '--listen',
                        help='start active processing on specified interface',
                        metavar='INTERFACE')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    for pcap in args.files:
        manager.process_pcap(pcap)
