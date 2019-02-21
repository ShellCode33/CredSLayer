import unittest
from scapy.all import *


class SessionsTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_sessions_extract(self):
        from nce.core.manage import session_extractor

        pcap = rdpcap("samples/irc1.pcap")
        sessions = pcap.sessions(session_extractor)
        self.assertTrue(len(sessions) == 1)
        self.assertTrue("10.10.10.10:59604 | 10.11.11.11:80" in sessions)

        pcap = rdpcap("samples/irc2.pcap")
        sessions = pcap.sessions(session_extractor)
        self.assertTrue(len(sessions) == 3)
        self.assertTrue("10.240.0.2:31337 | 10.240.0.3:48132" in sessions)
        self.assertTrue("10.240.0.2:31337 | 10.240.0.4:57728" in sessions)
        self.assertTrue("10.240.0.2:31337 | 10.240.0.5:42277" in sessions)

        pcap = rdpcap("samples/ftp.pcap")
        sessions = pcap.sessions(session_extractor)
        self.assertTrue(len(sessions) == 1)
        self.assertTrue("10.10.30.26:43958 | 129.21.171.72:21" in sessions)
