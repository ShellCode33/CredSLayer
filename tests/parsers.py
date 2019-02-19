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
