# NetCredzMiner

![alt python_version](https://img.shields.io/badge/python-3.5+-informational.svg)
![alt tests_coverage](https://img.shields.io/badge/tests%20coverage-94%25-success.svg)

You thought PCredz was good ? Net-creds even better ? Try this out, you'll be surprised !

NCM goal is to look for credentials and other useful stuff in network captures. Two modes are available, pcap scanning and active processing. The latest listens for packets on a chosen interface and dynamically extracts everything it can.

This tool is really helpful if you're a pentester or if you want to scan your own network to see if anything critical is sent over. 

The code is based on [pyshark](https://github.com/KimiNewt/pyshark). It basically gives an access to Wireshark dissectors, resulting in an incredible amount of supported protocols. 

# Features

Right now, NetCredzMiner supports the following protocols:
* FTP
* SMTP / IMAP / POP3
* Telnet
* HTTP
* LDAP
* HTTP

It is also able to look for email addresses, credit card numbers, visited URLs.

Because it uses Wireshark dissectors, it's really easy to write new ones. Understand: more will come.

# Tests

A lot of unit tests have been made in order to prevent unexpected behavior from happening. Of course no software is perfect, if you spot anything weird, please open an issue.

**Note:** This tool has been tested using tshark 3.0.0 and Python 3.7

# Credits

* Wireshark for their [pcaps](https://wiki.wireshark.org/SampleCaptures)

* [moloch](https://github.com/aol/moloch) for their [pcaps](https://github.com/aol/moloch/tree/master/tests/pcap)

* [asecuritysite](https://asecuritysite.com) for their [pcaps](https://asecuritysite.com/forensics/pcap)
