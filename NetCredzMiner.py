#!/usr/bin/python3
# coding: utf-8
import argparse
import os
import traceback

import argcomplete

from ncm.core import manager, logger

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Helps you find credentials and other interesting stuff in network captures')
    parser.add_argument("pcapfiles",
                        nargs='*',
                        help='pcap files you want to analyse.')
    parser.add_argument('-l', '--listen',
                        help='start active processing on specified interface',
                        metavar='INTERFACE')
    parser.add_argument('-d', '--disable-url-logging',
                        help='disable URL logging, can be spammy')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.listen and not args.pcapfiles:
        parser.error("Nothing to do...")

    if args.listen:

        if os.geteuid() != 0:
            print("You must be root to listen on an interface.")
            exit(1)

        manager.active_processing(args.listen)

    for pcap in args.pcapfiles:

        try:
            manager.process_pcap(pcap)
        except Exception as e:
            error_str = str(e)

            if error_str.startswith("[Errno"):  # Clean error message
                errno_end_index = error_str.find("]") + 2
                error_str = error_str[errno_end_index:]
                logger.error(error_str)

            else:
                traceback.print_exc()
