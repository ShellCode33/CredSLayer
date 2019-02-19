#!/usr/bin/python3
# coding: utf-8

from nce.core import manage

if __name__ == "__main__":
    print("NetCredzExtractor is starting...")
    manage.process_pcap("tests/samples/telnet-cooked.pcap")
