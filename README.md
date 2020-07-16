# CredSLayer

![alt python_version](https://img.shields.io/badge/python-3.5+-informational.svg?style=for-the-badge)
![alt tests_coverage](https://img.shields.io/badge/tests%20coverage-94%25-success.svg?style=for-the-badge)
[![alt documentation](https://img.shields.io/badge/documentation-critical.svg?style=for-the-badge)](https://shellcode33.github.io/CredSLayer/)

CredSLayer goal is to look for credentials and other useful stuff in network captures. Two modes are available, pcap scanning and active processing. The latest listens for packets on a chosen interface and dynamically extracts everything it can.

This tool has been heavily inspired by [Pcredz](https://github.com/lgandx/PCredz) and [net-creds](https://github.com/DanMcInerney/net-creds) but is built with extensibility in mind.
Pcredz and net-creds are great, but they are really hard to maintain and improve.
Unlike these tools which are using regex and raw bytes parsing, CredSLayer takes advantage of Wireshark dissectors which have proven over time to be pretty accurate and reliable.
It makes it really easy to add support for new protocols.


This tool can be really helpful if you're doing IT security or if you want to scan your own network to see if anything critical is transmitted.

![alt credslayer_output_example](https://github.com/ShellCode33/CredSLayer/raw/master/docs/example.png)

# Features

CredSLayer doesn't waste your time with invalid credentials, it makes sure credentials are valid.
Yet if it's not able to tell whether they're valid or not, what has been found will be printed out anyway. 

Right now, CredSLayer supports the following protocols:
* FTP
* SMTP / IMAP / POP3
* Telnet
* HTTP
* LDAP
* SNMP
* MySQL / PostgreSQL
* NTLMSSP
* Kerberos coming soon...

It is also able to look for email addresses and credit card numbers.

**Note:** To prevent false positives and performance issues, tshark (the Wireshark underlying engine) identifies protocols based on port numbers to know which dissector to use on which packets. A few protocols however have heuristic analysis to guess the protocol on different ports than the usual ones (such as HTTP). See the [limitation chapter](https://shellcode33.github.io/CredSLayer/getting-started/limitations.html) in the documentation. To address this issue, CredSLayer has a `--map` parameter, it enables you to map a (range of) port(s) to a specific protocol. This way you will be able to sniff credentials going to a specific service on a specific port you are aware of.

# Install

You need `tshark` installed and Python >= 3.5. On some distribution tshark in shipped within the `wireshark` package. 

Then simply install using :

```
$ pip install credslayer
```

I recommend you use a [virtualenv](https://docs.python.org/3/library/venv.html) to prevent conflicts.

# Usage

```
$ credslayer -h
usage: credslayer [-h] [-l INTERFACE] [-s {enable,disable}] [-f IP]
                     [-m PORT:PROTOCOL] [--debug]
                     [pcapfiles [pcapfiles ...]]

Helps you find credentials and other interesting stuff in network captures

positional arguments:
  pcapfiles             pcap files you want to analyse.

optional arguments:
  -h, --help            show this help message and exit
  -l INTERFACE, --listen INTERFACE
                        start active processing on specified interface
  -s {enable,disable}, --string-inspection {enable,disable}
                        let you specify if you want to look for interesting
                        strings (email addresses, credit cards, ...) in
                        network captures. Pretty heavy on the CPU. Enabled by
                        default on pcap files, disabled on live captures.
  -f IP, --filter IP    only show packets involving the specified IP.
  -m PORT:PROTOCOL, --map PORT:PROTOCOL
                        map a port to a protocol
  --debug               put CredSLayer and pyshark in debug mode.
```

# Get involved

Thanks to Wireshark dissectors, it's really easy to write new protocols support, you're welcome to contribute !

Contributing doesn't necessarily mean writing code. You can simply contribute by opening new issues on Github if you spot any bug or if you would like to see something added to the tool.

To learn how to create support for a new protocol, head over to the [documentation](https://shellcode33.github.io/CredSLayer/contribute/create-parser.html).

# Credits

* CredSLayer is based on [pyshark](https://github.com/KimiNewt/pyshark), a tshark Python wrapper

* Wireshark for their [pcaps](https://wiki.wireshark.org/SampleCaptures)

* [moloch](https://github.com/aol/moloch) for their [pcaps](https://github.com/aol/moloch/tree/master/tests/pcap)

* [asecuritysite](https://asecuritysite.com) for their [pcaps](https://asecuritysite.com/forensics/pcap)
