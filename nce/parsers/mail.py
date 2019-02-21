# coding: utf-8

from nce.core import logger
from base64 import b64decode


def analyse(packets):
    logger.debug("Mail analysis...")

    credentials = []
    strings = []

    for packet in packets:

        # If there is no payload in that packet, we're not interested
        if not hasattr(packet, "load"):
            continue

        # We only want strings, no need to parse bytes with telnet
        try:
            string = packet.load.decode()
            strings.append(string.strip())
        except UnicodeDecodeError:
            continue

    auth_process = False
    username = password = None

    # ------------------------  SMTP  ------------------------
    for string in strings:
        if string.startswith("AUTH"):
            auth_process = True

        elif auth_process:
            if string.startswith("235"):
                credentials.append((username, password))
                break

            elif not string.startswith("334"):
                if username is None:
                    username = b64decode(string).decode()
                else:
                    password = b64decode(string).decode()
    # --------------------------------------------------------

    username = password = None

    # ------------------------  IMAP  ------------------------
    for string in strings:
        tokens = string.split(" ")

        if len(tokens) < 3:
            continue

        if tokens[1] == "OK" and tokens[2] == "LOGIN" and username is not None and password is not None:
            credentials.append((username, password))
            break

        elif tokens[1] == "LOGIN":
            username = tokens[2][1:-1]  # [1:-1] to remove " " surrounding the credentials
            password = "".join(tokens[3:])[1:-1]  # we join what's left in `tokens` because a space could be in the pass
    # --------------------------------------------------------

    # TODO : POP3

    return credentials


