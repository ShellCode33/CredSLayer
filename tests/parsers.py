import unittest
from scapy.all import *


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        from nce.parsers import telnet

        telnet_pcap = rdpcap("samples/telnet-cooked.pcap")
        credentials = telnet.parse(telnet_pcap)
        self.assertTrue(credentials == ('fake', 'user'))

        telnet_pcap = rdpcap("samples/telnet-raw.pcap")
        credentials = telnet.parse(telnet_pcap)
        self.assertTrue(credentials == ('fake', 'user'))

    def test_ftp(self):
        from nce.parsers import ftp

        ftp_pcap = rdpcap("samples/ftp.pcap")
        credentials = ftp.parse(ftp_pcap)
        self.assertTrue(credentials == ('anonymous', 'ftp@example.com'))

    def test_irc(self):
        from nce.parsers import irc
        from nce.core.manage import session_extractor

        irc_pcap = rdpcap("samples/irc1.pcap")
        credentials = irc.parse(irc_pcap)
        self.assertTrue(credentials == ('THE-USER', None))

        irc_pcap = rdpcap("samples/irc2.pcap")
        sessions = list(irc_pcap.sessions(session_extractor).values())

        credentials = irc.parse(sessions[0])
        self.assertTrue(credentials == ('Matir', None))

        credentials = irc.parse(sessions[1])
        self.assertTrue(credentials == ('andrewg', None))

        credentials = irc.parse(sessions[2])
        self.assertTrue(credentials == ('itsl0wk3y', None))
