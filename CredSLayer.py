#!/usr/bin/python3
# coding: utf-8
import socket

import argparse
import os
import traceback

import argcomplete

from csl.core import manager, logger

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Helps you find credentials and other interesting stuff in network captures')
    parser.add_argument("pcapfiles",
                        nargs='*',
                        help='pcap files you want to analyse.')
    parser.add_argument('-l', '--listen',
                        help='start active processing on specified interface',
                        metavar='INTERFACE')
    parser.add_argument('-s', '--string-inspection',
                        choices=["enable", "disable"],
                        help='let you specify if you want to look for interesting strings (email addresses, '
                             'credit cards, ...) in network captures. Pretty heavy on the CPU. '
                             'Enabled by default on pcap files, disabled on live captures.')
    parser.add_argument('-f', '--filter',
                        metavar='IP',
                        help='only show '
                             'packets involving the specified IP.')
    parser.add_argument('-m', '--map',
                        action='append',
                        metavar='PORT:PROTOCOL',
                        help='map a port to a protocol')
    parser.add_argument('--debug', action='store_true',
                        help='put CredSLayer and pyshark in debug mode.')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.listen and not args.pcapfiles:
        parser.error("Nothing to do...")

    string_inspection = None

    if args.string_inspection == "enable":
        string_inspection = True
    elif args.string_inspection == "disable":
        string_inspection = False

    ip_filter = None

    if args.filter:

        # tshark display filter
        try:
            socket.inet_aton(args.filter)
            ip_filter = "ip.src == {0} or ip.dst == {0}".format(args.filter)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, args.filter)
                ip_filter = "ipv6.src == {0} or ipv6.dst == {0}".format(args.filter)
            except socket.error:
                parser.error("Invalid IP address filter")

        # dumpcap capture filter
        if args.listen:
            ip_filter = "host " + args.filter

    decode_map = None

    if args.map:
        decode_map = {}

        for map in args.map:
            tokens = map.split(":")

            if len(tokens) != 2:
                parser.error("Invalid port mapping")

            decode_map["tcp.port==" + tokens[0]] = tokens[1]
            logger.info("CredSLayer will decode traffic on '{}' as '{}'".format(*tokens))

    if args.listen:

        if os.geteuid() != 0:
            print("You must be root to listen on an interface.")
            exit(1)

        manager.active_processing(args.listen,
                                  must_inspect_strings=string_inspection,
                                  tshark_filter=ip_filter,
                                  debug=args.debug,
                                  decode_as=decode_map)
        exit(0)

    for pcap in args.pcapfiles:

        try:
            manager.process_pcap(pcap,
                                 must_inspect_strings=string_inspection,
                                 tshark_filter=ip_filter,
                                 debug=args.debug,
                                 decode_as=decode_map)

        except Exception as e:
            error_str = str(e)

            if error_str.startswith("[Errno"):  # Clean error message
                errno_end_index = error_str.find("]") + 2
                error_str = error_str[errno_end_index:]
                logger.error(error_str)

            else:
                traceback.print_exc()
