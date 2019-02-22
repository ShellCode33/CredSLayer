# coding: utf-8

from scapy.plist import PacketList
from nce.core import utils
from typing import Set
import re

email_regex = re.compile(
    r"(?:[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(?:\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    r'|^"(?:[\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'  # quoted-string
    r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}', re.IGNORECASE)  # domain

# TODO: improve regex with https://stackoverflow.com/questions/9315647/regex-credit-card-number-tests
credit_card_regex = re.compile(
    r"(?:4[0-9]{12}(?:[0-9]{3})?"  # Visa
    r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"  # MasterCard
    r"|3[47][0-9]{13}"  # American Express
    r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"  # Diners Club
    r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
    r"|(?:2131|1800|35\d{3})\d{11}"  # JCB
    r")")

# Prevent logging of stuff already logged
emails_already_found = set()
credit_cards_already_found = set()


def extract_emails(packets: PacketList) -> Set:
    emails = set()
    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    for string in strings:
        emails_found = email_regex.findall(string)

        if len(emails_found) > 0:
            for email_found in emails_found:
                if email_found not in emails_already_found:
                    emails.add(email_found)
                    emails_already_found.add(email_found)

    return emails


# TODO : this is prone to a lot of false positives (see imap.pcap)
#  to solve this we have to adapt the regex, check for a separator
#  between numbers and make sure there's no number surrounding the whole thing
def extract_credit_cards(packets: PacketList) -> Set:
    credit_cards = set()
    strings = utils.extract_strings_from(packets)
    strings = "".join(strings)
    strings = re.split(r"[\n\r]+", strings)

    for string in strings:
        string = string.replace("-", "").replace(" ", "")  # We clean the string to improve regex matching
        credit_cards_found = credit_card_regex.findall(string)

        if len(credit_cards_found) > 0:
            for credit_card_found in credit_cards_found:
                if credit_card_found not in credit_cards_already_found:
                    credit_cards.add(credit_card_found)
                    credit_cards_already_found.add(credit_card_found)

    return credit_cards
