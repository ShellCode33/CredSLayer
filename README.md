# NetCredzMiner

![alt python_version](https://img.shields.io/badge/python-3.5+-informational.svg)
![alt tests_coverage](https://img.shields.io/badge/tests%20coverage-94%25-success.svg)

NCM goal is to look for credentials and other useful stuff in network captures. Two modes are available, pcap scanning and active processing. The latest listens for packets on a chosen interface and dynamically extracts everything it can.

This tool is really helpful if you're a pentester or if you want to scan your own network to see if anything critical is sent over the network. 

NCM is a complete rewrite of NetCreds and PCredz. It is written using Python3 and aims to be way more extensible and easier to maintain. 

It is also heavily tested to prevent any unexpected behavior. Those tests also check false positives between parsers (even if it can't be fully prevented). 

# Features

NetCredzExtractor is able to extract credentials in the following protocols:
* FTP
* IRC
* SMTP / IMAP / POP3
* Telnet
* HTTP

It is also able to look for email addresses, credit card numbers, visited URLs.

# Credits

Big thank you to :

* the authors and contributors of [PCredz](https://github.com/lgandx/PCredz) and [net-creds](https://github.com/DanMcInerney/net-creds). Many parts of their code have been reused

* Wireshark for their [pcaps](https://wiki.wireshark.org/SampleCaptures)

* [moloch](https://github.com/aol/moloch) for their [pcaps](https://github.com/aol/moloch/tree/master/tests/pcap)

* [asecuritysite](https://asecuritysite.com) for their [pcaps](https://asecuritysite.com/forensics/pcap)
