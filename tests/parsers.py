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
        credentials = telnet.analyse(telnet_pcap)
        self.assertTrue(credentials == [('fake', 'user')])

        telnet_pcap = rdpcap("samples/telnet-raw.pcap")
        credentials = telnet.analyse(telnet_pcap)
        self.assertTrue(credentials == [('fake', 'user')])

    def test_ftp(self):
        from nce.parsers import ftp

        ftp_pcap = rdpcap("samples/ftp.pcap")
        credentials = ftp.analyse(ftp_pcap)
        self.assertTrue(credentials == [('anonymous', 'ftp@example.com')])

    def test_irc(self):
        from nce.parsers import irc

        irc_pcap = rdpcap("samples/irc1.pcap")
        credentials = irc.analyse(irc_pcap)
        self.assertTrue(credentials == [('THE-USER', None)])

        irc_pcap = rdpcap("samples/irc2.pcap")
        credentials = irc.analyse(irc_pcap)
        self.assertTrue(credentials == [('Matir', None), ('andrewg', None), ('itsl0wk3y', None)])
