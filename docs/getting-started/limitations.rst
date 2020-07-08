Limitations
===========

One of the biggest issue is probably performance. CredSLayer relies on pyshark (a wrapper arround tshark) and both are written in Python. I personally find it to be a great choice for a community project because it's easy to read and many people know how to write Python code.
But unfortunately Python is pretty slow when it comes to processing a lot of data. Therefore CredSLayer will obviously not work very well if you run it on a backbone, but hopefully people will find it to be enough for most of their needs.

To prevent false positives, false negatives and performance issues, **Wireshark identifies most protocols based on their default port number**. It means that if, for example, a telnet server is running on the port 1337 (which is not default) Wireshark will not be able to identify it and will therefore not process it.

However, Wireshark implements mechanisms called **heuristic dissectors**, it enables Wireshark (and by extension CredSLayer) to identify **some** protocols on other ports than the default one. Here's what Wireshark's documentation says about heuristic dissectors :

.. code-block:: text

    When Wireshark "receives" a packet, it has to find the right dissector to
    start decoding the packet data. Often this can be done by known conventions,
    e.g. the Ethernet type 0x0800 means "IP on top of Ethernet" - an easy and
    reliable match for Wireshark.

    Unfortunately, these conventions are not always available, or (accidentally
    or knowingly) some protocols don't care about those conventions and "reuse"
    existing "magic numbers / tokens".

    For example TCP defines port 80 only for the use of HTTP traffic. But, this
    convention doesn't prevent anyone from using TCP port 80 for some different
    protocol, or on the other hand using HTTP on a port number different than 80.

    To solve this problem, Wireshark introduced the so called heuristic dissector
    mechanism to try to deal with these problems.

Thanks to this, some easy-to-identify-protocols can be detected on any port. This is the case of HTTP which is pretty easy to spot because its payloads always start with a method (GET, POST, OPTIONS, etc.).

To enable CredSLayer to still be able to analyse "hidden" protocols, the CLI has a ``--map`` parameter which enables you to map a (range of) port(s) to a specific protocol. This way you will be able to sniff credentials going to a specific service on a specific port you are aware of.
