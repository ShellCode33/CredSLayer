# coding: utf-8

import os
import unittest

from pyshark import FileCapture

from credslayer.core import extract, utils
from credslayer.core.manager import process_pcap
from credslayer.core.session import Session
from credslayer.core.utils import Credentials, CreditCard


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

        credentials_list = process_pcap("samples/telnet.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('shellcode', 'shellcode') in credentials_list)
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
        self.assertTrue(Credentials("tfoerste", hash="eefd6d5562851bc5966a0b41236ae3f2315efcc4",
                                    context={"salt": ">~$4uth,", "salt2": ">612IWZ>fhWX"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/mysql2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("user10", hash="55ee72f0c6694cbb3a104eb97f8ee32a6a91f8b1",
                                    context={"salt": "]E!r<uX8", "salt2": "Of2c!tIM)\"n'"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_pgsql(self):
        credentials_list = process_pcap("samples/pgsql.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("oryx", hash="ceffc01dcde7541829deef6b5e9c9142",
                                    context={"salt": "ad44ff54", "auth_type": "md5", "database": "mailstore"})
                        in credentials_list)
        self.assertTrue(Credentials("oryx", hash="f8f8b884b4ef7cc9ee95e69868cdfa5e",
                                    context={"salt": "f211a3ed", "auth_type": "md5", "database": "mailstore"})
                        in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

        credentials_list = process_pcap("samples/pgsql-nopassword.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("user", context={"database": "dbdb"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_ntlmssp(self):
        credentials_list = process_pcap("samples/smb-ntlm.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv2'},
                                                         hash="Willi Wireshark::DESKTOP-2AEFM7G:78f8f6206e882559:8149b0"
                                                              "b2a73a191141bda07d1ed18434:01010000000000000bd7d7878527d"
                                                              "201146f94347775321c0000000002001e004400450053004b0054004"
                                                              "f0050002d00560031004600410030005500510001001e00440045005"
                                                              "3004b0054004f0050002d00560031004600410030005500510004001"
                                                              "e004400450053004b0054004f0050002d00560031004600410030005"
                                                              "500510003001e004400450053004b0054004f0050002d00560031004"
                                                              "6004100300055005100070008000bd7d7878527d2010600040002000"
                                                              "0000800300030000000000000000100000000200000ad865b6d08a95"
                                                              "d0e76a94e2ca013ab3f69c4fd945cca01b277700fd2b305ca010a001"
                                                              "00000000000000000000000000000000000090028006300690066007"
                                                              "3002f003100390032002e003100360038002e003100390039002e003"
                                                              "10033003300000000000000000000000000")])

        credentials_list = process_pcap("samples/smb-ntlm2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv2'},
                                                         hash="administrator:::26de2c0b3abaaa1c:711d6cb05614bc240ca7e2a"
                                                              "38568ff85:0101000000000000e652e41aa7b4d401dac9a62e4db292"
                                                              "6b000000000200060046004f004f000100100044004600530052004f"
                                                              "004f00540031000400100066006f006f002e00740065007300740003"
                                                              "00220064006600730072006f006f00740031002e0066006f006f002e"
                                                              "0074006500730074000500100066006f006f002e0074006500730074"
                                                              "0007000800e652e41aa7b4d40100000000")])

        credentials_list = process_pcap("samples/smb-ntlm3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv1'},
                                                         hash="administrator::VNET3:42c09b264cbc46690000000000000000000"
                                                              "0000000000000:9cd7e4af2d7e934adc9b307231a958539b3d2c368b"
                                                              "964cea:28a3a326a53fa6f5")])

        remaining_credentials = process_pcap("samples/http-ntlm.pcap").get_remaining_content()
        remaining_credentials = [c[1] for c in remaining_credentials]  # Only get Credentials from the tuple

        print(remaining_credentials)

        self.assertTrue(len(remaining_credentials) == 6)
        self.assertTrue(Credentials(hash="administrator::example:ea46e3a07ea448d200000000000000000000000000000000:"
                                         "4d626ea83a02eee710571a2b84241788bd21e3a66ddbf4a5"
                                         ":CHALLENGE_NOT_FOUND") in remaining_credentials)


class ManagerTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_malformed(self):
        from credslayer.core import manager
        pcap = FileCapture("samples/smb-crash.pcap")
        self.assertRaises(manager.MalformedPacketException, manager._process_packet, Session(pcap[8]), pcap[8], False)
        pcap.close()

    def test_protocol_decode_as(self):
        from credslayer.core import manager
        credentials_list = manager.process_pcap("samples/telnet-hidden.pcap",
                                                decode_as={"tcp.port==1337": "telnet"})\
                                  .get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("shellcode", "shellcode") in credentials_list)


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
        from credslayer.core.session import SessionsManager

        sessions = SessionsManager()

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
        self.assertTrue("UDP 172.31.19.54 <-> 172.31.19.73" in sessions)
        self.assertTrue("UDP 172.31.19.73 <-> 224.0.1.35" in sessions)
        self.assertTrue("UDP 172.31.19.255 <-> 172.31.19.73" in sessions)

        # TODO: add more session tests
