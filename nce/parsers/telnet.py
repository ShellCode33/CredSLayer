# coding: utf-8

telnet_stream = []

def parse(pkt):

    if not hasattr(pkt, "load"):
        return

    # We only want strings, no need to parse bytes with telnet
    try:
        string = pkt.load.decode()
        telnet_stream.append(string)
    except UnicodeDecodeError:
        return
