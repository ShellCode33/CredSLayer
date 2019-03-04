import unittest
from scapy.all import *

from nce.core import extract
from nce.core.utils import Credentials
from nce.parsers import parsers, telnet, irc, ftp, mail, http


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        telnet_pcap = rdpcap("samples/telnet-cooked.pcap")
        credentials_list = telnet.analyse(telnet_pcap)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)

        telnet_pcap = rdpcap("samples/telnet-raw.pcap")
        credentials_list = telnet.analyse(telnet_pcap)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)

        telnet_pcap = rdpcap("samples/telnet-raw2.pcap")
        credentials_list = telnet.analyse(telnet_pcap)
        self.assertTrue(Credentials('Administrator', 'napier') in credentials_list)

    def test_ftp(self):
        ftp_pcap = rdpcap("samples/ftp.pcap")
        credentials_list = ftp.analyse(ftp_pcap)
        self.assertTrue(Credentials('anonymous', 'ftp@example.com') in credentials_list)

    def test_irc(self):
        irc_pcap = rdpcap("samples/irc1.pcap")
        credentials_list = irc.analyse(irc_pcap)
        self.assertTrue(Credentials('THE-USER') in credentials_list)

        irc_pcap = rdpcap("samples/irc2.pcap")
        credentials_list = irc.analyse(irc_pcap)
        self.assertTrue(Credentials('Matir') in credentials_list)
        self.assertTrue(Credentials('andrewg') in credentials_list)
        self.assertTrue(Credentials('itsl0wk3y') in credentials_list)

    def test_smtp(self):
        pcap_smtp = rdpcap("samples/smtp.pcap")
        credentials_list = mail.analyse(pcap_smtp)
        self.assertTrue(Credentials('gurpartap@patriots.in', 'punjab@123') in credentials_list)

    def test_imap(self):
        pcap_smtp = rdpcap("samples/imap.pcap")
        credentials_list = mail.analyse(pcap_smtp)
        self.assertTrue(Credentials('neulingern', 'XXXXXX') in credentials_list)

    def test_pop(self):
        pcap_pop = rdpcap("samples/pop3.pcap")
        credentials_list = mail.analyse(pcap_pop)
        self.assertTrue(Credentials('digitalinvestigator@networksims.com', 'napier123') in credentials_list)

    def test_http_basic_auth(self):
        pcap_http = rdpcap("samples/http-basic-auth.pcap")
        credentials_list = http.analyse(pcap_http)
        self.assertTrue(Credentials('test', 'test') in credentials_list)
        self.assertFalse(Credentials('test', 'fail') in credentials_list)
        self.assertFalse(Credentials('test', 'fail2') in credentials_list)
        self.assertFalse(Credentials('test', 'fail3') in credentials_list)

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

        pcap = rdpcap("samples/telnet-raw2.pcap")
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

        pcap = rdpcap("samples/pop3.pcap")
        parsers_filtered = parsers.copy()
        parsers_filtered.remove(mail)

        for parser in parsers_filtered:
            self.assertTrue(len(parser.analyse(pcap)) == 0)


class ExtractTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_extract_emails(self):
        pcap = rdpcap("samples/imap.pcap")
        emails_found = extract.extract_emails(pcap)
        self.assertTrue("nutmeg12s@hotmail.com" in emails_found)
        self.assertTrue("SharpJDs@yahoo.com" in emails_found)
        self.assertTrue("hardcase_890@yahoo.com" in emails_found)
        self.assertTrue("bandy_34@hotmail.com" in emails_found)

    def test_extract_credit_cards(self):
        pcap = rdpcap("samples/smtp-creditcards.pcap")
        credit_cards_found = extract.extract_credit_cards(pcap)
        self.assertTrue("4321444432143212" in credit_cards_found)
        self.assertTrue("5555555555555555" in credit_cards_found)
        self.assertTrue("4111400043213210" in credit_cards_found)

        # TODO : check false positives
        # pcap = rdpcap("samples/imap.pcap")
        # credit_cards_found = extract.extract_credit_cards(pcap)
        # self.assertTrue(len(credit_cards_found) == 0)


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
