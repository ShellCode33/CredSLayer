import unittest
from scapy.all import *

from nce.parsers import parsers
from nce.parsers import telnet, irc, ftp, mail


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        telnet_pcap = rdpcap("samples/telnet-cooked.pcap")
        credentials = telnet.analyse(telnet_pcap)
        self.assertTrue(credentials == [('fake', 'user')])

        telnet_pcap = rdpcap("samples/telnet-raw.pcap")
        credentials = telnet.analyse(telnet_pcap)
        self.assertTrue(credentials == [('fake', 'user')])

    def test_ftp(self):
        ftp_pcap = rdpcap("samples/ftp.pcap")
        credentials = ftp.analyse(ftp_pcap)
        self.assertTrue(credentials == [('anonymous', 'ftp@example.com')])

    def test_irc(self):
        irc_pcap = rdpcap("samples/irc1.pcap")
        credentials = irc.analyse(irc_pcap)
        self.assertTrue(credentials == [('THE-USER', None)])

        irc_pcap = rdpcap("samples/irc2.pcap")
        credentials = irc.analyse(irc_pcap)
        self.assertTrue(credentials == [('Matir', None), ('andrewg', None), ('itsl0wk3y', None)])

    def test_smtp(self):
        pcap_smtp = rdpcap("samples/smtp.pcap")
        credentials = mail.analyse(pcap_smtp)
        self.assertTrue(credentials == [('gurpartap@patriots.in', 'punjab@123')])

    def test_imap(self):
        pcap_smtp = rdpcap("samples/imap.pcap")
        credentials = mail.analyse(pcap_smtp)
        self.assertTrue(credentials == [('neulingern', 'XXXXXX')])

    def test_pop(self):
        pass

    def test_false_positives(self):
        pcap = rdpcap("samples/telnet-cooked.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(telnet)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/telnet-raw.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(telnet)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/ftp.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(ftp)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/irc1.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(irc)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/irc2.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(irc)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/smtp.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(mail)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)

        pcap = rdpcap("samples/imap.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(mail)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)


class SessionsTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_sessions_extract(self):
        from nce.core.utils import session_extractor

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
