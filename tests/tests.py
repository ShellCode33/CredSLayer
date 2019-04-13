import unittest

import os
from typing import List

from pyshark import FileCapture
from ncm.core import extract
from ncm.core.utils import Credentials, CreditCard
from ncm.parsers import parsers


def _extract_creds_from(pcap_filename, parser_to_use) -> List[Credentials]:
    pcap = FileCapture(pcap_filename)
    parser = parsers[parser_to_use]
    credentials_list = []

    for packet in pcap:
        if parser_to_use in packet:  # If the layer is in the packet
            credentials_list.append(parser.analyse(packet))

    pcap.close()
    return credentials_list


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        self.assertTrue(Credentials('fake', 'user') in _extract_creds_from("samples/telnet-cooked.pcap", "telnet"))
        self.assertTrue(Credentials('fake', 'user') in _extract_creds_from("samples/telnet-raw.pcap", "telnet"))
        self.assertTrue(Credentials('Administrator', 'napier') in _extract_creds_from("samples/telnet-raw2.pcap", "telnet"))

    def test_ftp(self):
        self.assertTrue(Credentials('anonymous', 'ftp@example.com') in _extract_creds_from("samples/ftp.pcap", "ftp"))

    def test_smtp(self):
        self.assertTrue(Credentials('gurpartap@patriots.in', 'punjab@123') in _extract_creds_from("samples/smtp.pcap", "smtp"))

    def test_imap(self):
        self.assertTrue(Credentials('neulingern', 'XXXXXX') in _extract_creds_from("samples/imap.pcap", "imap"))

    def test_pop(self):
        self.assertTrue(Credentials('digitalinvestigator@networksims.com', 'napier123') in _extract_creds_from("samples/pop3.pcap", "pop"))

    def test_http_basic_auth(self):
        credentials_list = _extract_creds_from("samples/http-basic-auth.pcap", "http")
        self.assertTrue(Credentials('test', 'test') in credentials_list)
        self.assertFalse(Credentials('test', 'fail') in credentials_list)
        self.assertFalse(Credentials('test', 'fail2') in credentials_list)
        self.assertFalse(Credentials('test', 'fail3') in credentials_list)

    def test_http_post_auth(self):
        self.assertTrue(Credentials('toto', 'Str0ngP4ssw0rd') in _extract_creds_from("samples/http-post-auth.pcap", "http"))

    def test_http_get_auth(self):
        self.assertTrue(Credentials('admin', 'qwerty1234') in _extract_creds_from("samples/http-get-auth.pcap", "http"))

    def test_ldap(self):
        credentials_list = _extract_creds_from("samples/ldap-simpleauth.pcap", "ldap")
        self.assertTrue(Credentials("xxxxxxxxxxx@xx.xxx.xxxxx.net", "passwor8d1") in credentials_list)
        self.assertTrue(Credentials("CN=xxxxxxxx,OU=Users,OU=Accounts,DC=xx,"
                                    "DC=xxx,DC=xxxxx,DC=net", "/dev/rdsk/c0t0d0s0") in credentials_list)

    def test_snmp(self):
        credentials_list = _extract_creds_from("samples/snmp-v1.pcap", "snmp")
        self.assertTrue(Credentials(password="public") in credentials_list)

        credentials_list = _extract_creds_from("samples/snmp-v3.pcap", "snmp")
        self.assertTrue(Credentials(username="pippo") in credentials_list)
        self.assertTrue(Credentials(username="pippo2") in credentials_list)
        self.assertTrue(Credentials(username="pippo3") in credentials_list)
        self.assertTrue(Credentials(username="pippo4") in credentials_list)

class ExtractTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_extract_emails(self):
        pcap = FileCapture("samples/imap.pcap")
        emails_found = set()

        for packet in pcap:
            emails_found |= extract.extract_emails(packet)

        pcap.close()

        self.assertTrue(len(emails_found) >= 47)
        self.assertTrue("nutmeg12s@hotmail.com" in emails_found)
        self.assertTrue("SharpJDs@yahoo.com" in emails_found)
        self.assertTrue("hardcase_890@yahoo.com" in emails_found)

        # TODO: make this one work... The thing is, the email address is splitted in 2 different packets... Give up ?
        # self.assertTrue("bandy_34@hotmail.com" in emails_found)

        pcap = FileCapture("samples/ldap-simpleauth.pcap")
        emails_found.clear()

        for packet in pcap:
            emails_found |= extract.extract_emails(packet)

        pcap.close()

        self.assertTrue(len(emails_found) == 1)
        self.assertTrue("xxxxxxxxxxx@xx.xxx.xxxxx.net" in emails_found)

    def test_extract_credit_cards(self):
        pcap = FileCapture("samples/smtp-creditcards.pcap")

        credit_cards_found = set()

        for packet in pcap:
            credit_cards_found |= extract.extract_credit_cards(packet)

        pcap.close()

        self.assertTrue(CreditCard("Visa", "4111-4000-4321-3210") in credit_cards_found)
        self.assertTrue(CreditCard("Visa", "4321 4444 3214 3212") in credit_cards_found)
        self.assertTrue(CreditCard("Mastercard", "5555 5555 5555 5555") in credit_cards_found)

    def test_credit_cards_false_positives(self):
        pcap = FileCapture("samples/imap.pcap")
        credit_cards_found = set()

        for packet in pcap:
            credit_cards_found |= extract.extract_credit_cards(packet)

        pcap.close()
        self.assertTrue(len(credit_cards_found) == 0)


class SessionsTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_sessions_extract(self):
        from ncm.core.session import SessionList

        sessions = SessionList()

        pcap = FileCapture("samples/ftp.pcap")

        for packet in pcap:
            sessions.get_session_of(packet)

        pcap.close()

        self.assertTrue(len(sessions) == 1)
        self.assertTrue("TCP 10.10.30.26:43958 | 129.21.171.72:21" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/imap.pcap")

        for packet in pcap:
            if "tcp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        self.assertTrue(len(sessions) == 3)
        self.assertTrue("TCP 131.151.32.21:4167 | 131.151.37.122:143" in sessions)
        self.assertTrue("TCP 131.151.32.91:3614 | 131.151.37.122:1065" in sessions)
        self.assertTrue("TCP 131.151.32.91:1065 | 131.151.37.117:1065" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/snmp-v1.pcap")

        for packet in pcap:
            if "udp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        self.assertTrue(len(sessions) == 3)
        self.assertTrue("UDP 172.31.19.54 | 172.31.19.73" in sessions)
        self.assertTrue("UDP 172.31.19.73 | 224.0.1.35" in sessions)
        self.assertTrue("UDP 172.31.19.255 | 172.31.19.73" in sessions)
