import os
import unittest

from pyshark import FileCapture

from csl.core import extract, utils
from csl.core.manager import process_pcap
from csl.core.utils import Credentials, CreditCard


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        credentials_list = process_pcap("samples/telnet-cooked.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/telnet-raw.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/telnet-raw2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('Administrator', 'napier') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_ftp(self):
        credentials_list = process_pcap("samples/ftp.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('anonymous', 'ftp@example.com') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_smtp(self):
        credentials_list = process_pcap("samples/smtp.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('gurpartap@patriots.in', 'punjab@123') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_imap(self):
        credentials_list = process_pcap("samples/imap.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('neulingern', 'XXXXXX') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_pop(self):
        credentials_list = process_pcap("samples/pop3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('digitalinvestigator@networksims.com', 'napier123') in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

    def test_http_basic_auth(self):
        credentials_list = process_pcap("samples/http-basic-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('test', 'test') in credentials_list)
        self.assertFalse(Credentials('test', 'fail') in credentials_list)
        self.assertFalse(Credentials('test', 'fail2') in credentials_list)
        self.assertFalse(Credentials('test', 'fail3') in credentials_list)
        self.assertTrue(len(credentials_list) == 6)

    def test_http_post_auth(self):
        credentials_list = process_pcap("samples/http-post-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('toto', 'Str0ngP4ssw0rd') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_http_get_auth(self):
        credentials_list = process_pcap("samples/http-get-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('admin', 'qwerty1234') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_ldap(self):
        credentials_list = process_pcap("samples/ldap-simpleauth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("xxxxxxxxxxx@xx.xxx.xxxxx.net", "passwor8d1") in credentials_list)
        self.assertTrue(Credentials("CN=xxxxxxxx,OU=Users,OU=Accounts,DC=xx,"
                                    "DC=xxx,DC=xxxxx,DC=net", "/dev/rdsk/c0t0d0s0") in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

    def test_snmp(self):
        credentials_list = process_pcap("samples/snmp-v1.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials(password="public") in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/snmp-v3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials(username="pippo") in credentials_list)
        self.assertTrue(Credentials(username="pippo2") in credentials_list)
        self.assertTrue(Credentials(username="pippo3") in credentials_list)
        self.assertTrue(Credentials(username="pippo4") in credentials_list)
        self.assertTrue(len(credentials_list) == 4)

    def test_mysql(self):
        credentials_list = process_pcap("samples/mysql.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("tfoerste", hash="eefd6d5562851bc5966a0b41236ae3f2315efcc4", context={"salt": ">~$4uth,", "salt2": ">612IWZ>fhWX"})
                        in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/mysql2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("user10", hash="55ee72f0c6694cbb3a104eb97f8ee32a6a91f8b1", context={"salt": "]E!r<uX8", "salt2": "Of2c!tIM)\"n'"})
                        in credentials_list)
        self.assertTrue(len(credentials_list) == 1)


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
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            emails_found |= extract.extract_emails(strings)

        pcap.close()

        print(emails_found)

        self.assertTrue(len(emails_found) >= 46)
        self.assertTrue("nutmeg12s@hotmail.com" in emails_found)
        self.assertTrue("SharpJDs@yahoo.com" in emails_found)
        self.assertTrue("hardcase_890@yahoo.com" in emails_found)

        # TODO: make this one work... The thing is, the email address is splitted in 2 different packets... Give up ?
        # self.assertTrue("bandy_34@hotmail.com" in emails_found)

        pcap = FileCapture("samples/ldap-simpleauth.pcap")
        emails_found.clear()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            emails_found |= extract.extract_emails(strings)

        pcap.close()

        print(emails_found)

        self.assertTrue(len(emails_found) == 1)
        self.assertTrue("xxxxxxxxxxx@xx.xxx.xxxxx.net" in emails_found)

    def test_extract_credit_cards(self):
        pcap = FileCapture("samples/smtp-creditcards.pcap")

        credit_cards_found = set()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            credit_cards_found |= extract.extract_credit_cards(strings)

        pcap.close()

        print(credit_cards_found)

        self.assertTrue(CreditCard("Visa", "4111-4000-4321-3210") in credit_cards_found)
        self.assertTrue(CreditCard("Visa", "4321 4444 3214 3212") in credit_cards_found)
        self.assertTrue(CreditCard("Mastercard", "5555 5555 5555 5555") in credit_cards_found)

    def test_credit_cards_false_positives(self):
        pcap = FileCapture("samples/imap.pcap")
        credit_cards_found = set()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            credit_cards_found |= extract.extract_credit_cards(strings)

        pcap.close()

        print(credit_cards_found)
        self.assertTrue(len(credit_cards_found) == 0)


class SessionsTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_sessions_extract(self):
        from csl.core.session import SessionList

        sessions = SessionList()

        pcap = FileCapture("samples/ftp.pcap")

        for packet in pcap:
            sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 1)
        self.assertTrue("TCP 10.10.30.26:43958 <-> 129.21.171.72:21" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/imap.pcap")

        for packet in pcap:
            if "tcp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 3)
        self.assertTrue("TCP 131.151.32.21:4167 <-> 131.151.37.122:143" in sessions)
        self.assertTrue("TCP 131.151.32.91:3614 <-> 131.151.37.122:1065" in sessions)
        self.assertTrue("TCP 131.151.32.91:1065 <-> 131.151.37.117:1065" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/snmp-v1.pcap")

        for packet in pcap:
            if "udp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 3)
        self.assertTrue("UDP 172.31.19.73 <-> 172.31.19.54" in sessions)
        self.assertTrue("UDP 224.0.1.35 <-> 172.31.19.73" in sessions)
        self.assertTrue("UDP 172.31.19.255 <-> 172.31.19.73" in sessions)

        # TODO: add more session tests
