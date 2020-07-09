Welcome to CredSLayer's documentation!
======================================

CredSLayer's goal is to look for credentials and other useful stuff in network captures. Two modes are available, pcap scanning and active processing. The latest listens for packets on a chosen interface and extract on the fly valuable data.

This tool has been heavily inspired by Pcredz and net-creds but is built with extensibility in mind.
Pcredz and net-creds are great, but they are really hard to maintain and improve.
Unlike these tools which are using regex and raw bytes parsing, CredSLayer takes advantage of Wireshark dissectors which have proven to be pretty accurate and reliable.
It makes it really easy to add support for new protocols.

This tool is really helpful if you're doing IT security or if you want to scan your own network to see if anything critical is transmitted.

.. image:: example.png
    :width: 800
    :alt: CredSLayer output example


.. toctree::
    :hidden:
    :caption: Getting Started
    :maxdepth: 4

    getting-started/installation
    getting-started/usage-cli
    getting-started/usage-own-project
    getting-started/limitations


.. toctree::
    :hidden:
    :caption: Contribute
    :maxdepth: 4

    contribute/setup
    contribute/code-explanations
    contribute/create-parser
