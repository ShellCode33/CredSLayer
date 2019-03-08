# coding: utf-8

from scapy.plist import PacketList
from typing import Set
import re

from ncm.core import utils
from ncm.core.utils import CreditCard

email_regex = re.compile(
    r"(?:[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(?:\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    r'|^"(?:[\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'  # quoted-string
    r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}', re.IGNORECASE)  # domain

# Tries to match things that look like a credit card.
# Things like 11111111-11111111 will also match, that's why there's a second step to validate that data.
first_step_credit_card_regex = re.compile(r"(?:\s|^)(?:\d[ -]*?){13,16}(?:\s|$)")

# https://gist.github.com/michaelkeevildown/9096cd3aac9029c4e6e05588448a8841
second_step_credit_card_regex = re.compile(
    r"^(?P<AmericanExpress>3[47][0-9]{13})"
    r"|(?P<BCGlobal>(?:6541|6556)[0-9]{12})"
    r"|(?P<CarteBlanche>389[0-9]{11})"
    r"|(?P<DinersClub>3(?:0[0-5]|[68][0-9])[0-9]{11})"
    r"|(?P<Discover>65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|"
    r"(?:622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10}))"
    r"|(?P<InstaPayment>63[7-9][0-9]{13})"
    r"|(?P<JCB>(?:2131|1800|35\d{3})\d{11})"
    r"|(?P<KoreanLocal>9[0-9]{15})"
    r"|(?P<Laser>(?:6304|6706|6709|6771)[0-9]{12,15})"
    r"|(?P<Maestro>(?:5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15})"
    r"|(?P<Mastercard>(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})"
    r"|(?P<Solo>(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15})"
    r"|(?P<Switch>(?:4903|4905|4911|4936|6333|6759)[0-9]{12}|(?:4903|4905|4911|4936|6333|6759)[0-9]{14}|"
    r"(?:4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|"
    r"633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13})"
    r"|(?P<UnionPay>62[0-9]{14,17})"
    r"|(?P<Visa>4[0-9]{12}[0-9]{3}?)"
    r"|(?P<VisaMaster>9[0-9]{15})"
    r"$")

# Prevent logging of stuff already logged
emails_already_found = set()
credit_cards_already_found = set()


def extract_emails(packets: PacketList) -> Set:
    emails = set()
    strings = utils.extract_strings_splitted_on_new_lines_from(packets)

    for string in strings:
        emails_found = email_regex.findall(string)

        if len(emails_found) > 0:
            for email_found in emails_found:
                if email_found not in emails_already_found:
                    emails.add(email_found)
                    emails_already_found.add(email_found)

    return emails


def extract_credit_cards(packets: PacketList) -> Set[CreditCard]:
    credit_cards = set()
    strings = utils.extract_strings_splitted_on_new_lines_from(packets)

    def clean_credit_card(card):
        return card.replace(" ", "").replace("-", "")

    for string in strings:
        credit_cards_found = first_step_credit_card_regex.findall(string)

        for credit_card_found in credit_cards_found:
            credit_card_found = credit_card_found.strip()  # Remove potential whitespaces
            credit_card_match = second_step_credit_card_regex.match(clean_credit_card(credit_card_found))

            if credit_card_match and credit_card_found not in credit_cards_already_found:
                credit_cards.add(CreditCard(credit_card_match.lastgroup, credit_card_found))
                credit_cards_already_found.add(CreditCard(credit_card_match.lastgroup, credit_card_found))

    return credit_cards
