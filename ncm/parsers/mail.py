# coding: utf-8
import binascii
import re


from scapy.plist import PacketList
from ncm.core import logger, utils, extract
from ncm.core.utils import CredentialsList, Credentials
from base64 import b64decode


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("Mail analysis...")

    all_credentials = []
    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    auth_process = False
    username = password = None

    # Note : yes we loop through strings multiple times, it's not very efficient, but it's the best way to avoid false-

    # ------------------------  SMTP  ------------------------
    for string in strings:

        if string.startswith("AUTH"):
            auth_process = True

        elif auth_process:
            if string.startswith("235"):
                all_credentials.append(Credentials(username, password))
                break

            # TODO : disable auth_process on error

            elif not string.startswith("334"):
                try:
                    if username is None:
                        username = b64decode(string).decode()
                    else:
                        password = b64decode(string).decode()
                except (UnicodeDecodeError, binascii.Error):
                    continue
    # --------------------------------------------------------

    username = password = None

    # ------------------------  IMAP  ------------------------
    for string in strings:
        tokens = string.split(" ")

        if len(tokens) < 3:
            continue

        if tokens[1] == "OK" and tokens[2] == "LOGIN" and username is not None and password is not None:
            all_credentials.append(Credentials(username, password))
            break

        elif tokens[1] == "LOGIN":
            username = tokens[2][1:-1]  # [1:-1] to remove " " surrounding the credentials
            password = " ".join(tokens[3:])[1:-1]  # join what's left in `tokens` because a space could be in the pass
    # --------------------------------------------------------

    auth_process = False
    # ------------------------  POP3  ------------------------
    for string in strings:

        if string.startswith("AUTH PLAIN"):
            auth_process = True

        elif auth_process:

            if string.startswith("-ERR"):
                auth_process = False

            if string.startswith("+OK"):
                all_credentials.append(Credentials(username, password))
                break

            else:
                try:
                    auth_content = b64decode(string)
                    auth_content = auth_content.split(b"\x00")
                    username = auth_content[1].decode()
                    password = auth_content[2].decode()
                except (UnicodeDecodeError, binascii.Error):
                    continue

    # --------------------------------------------------------

    return all_credentials
