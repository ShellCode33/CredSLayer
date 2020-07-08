# coding: utf-8

import re
from typing import Set, List

from credslayer.core.utils import CreditCard

# This regex has been made in order to prevent false positives, theoretically it can miss a few addresses.
_email_regex = re.compile(r'(?:\t| |^|<|,|:)([^+\x00-\x20@<>/\\{}`^\'*:;=()%\[\],_\-"]'
                          r'[^\x00-\x20@<>/\\{}`^\'*:;=()%\[\],"]{2,63}@(?:[a-z0-9]{2,63}\.)+[a-z]{2,6})')

# Tries to match things that look like a credit card.
# Things like 11111111-11111111 will also match, that's why there's a second step to validate that data.
_first_step_credit_card_regex = re.compile(r"(?:\s|^)(?:\d[ -]*?){13,16}(?:\s|$)")

# https://gist.github.com/michaelkeevildown/9096cd3aac9029c4e6e05588448a8841
_second_step_credit_card_regex = re.compile(
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


def extract_emails(packet_strings: List[str]) -> Set[str]:
    """
    Parameters
    ----------
    packet_strings
        The list of strings to extract emails from.

    Returns
    -------
    Set[str]
        A set of emails found.
    """
    emails = set()

    for string in packet_strings:
        emails_found = _email_regex.findall(string)

        for email_found in emails_found:
            if email_found not in emails_already_found:
                emails.add(email_found)
                emails_already_found.add(email_found)

    return emails


def extract_credit_cards(packet_strings: List[str]) -> Set[CreditCard]:
    """
    Parameters
    ----------
    packet_strings
        The list of strings to extract credit cards from.

    Returns
    -------
    Set[CreditCard]
        A set of `CreditCard` tuple.
    """
    credit_cards = set()

    def clean_credit_card(card):
        return card.replace(" ", "").replace("-", "")

    for string in packet_strings:
        credit_cards_found = _first_step_credit_card_regex.findall(string)

        for credit_card_found in credit_cards_found:
            credit_card_found = credit_card_found.strip()  # Remove potential whitespaces
            credit_card_match = _second_step_credit_card_regex.match(clean_credit_card(credit_card_found))

            if credit_card_match and credit_card_found not in credit_cards_already_found:
                credit_cards.add(CreditCard(credit_card_match.lastgroup, credit_card_found))
                credit_cards_already_found.add(CreditCard(credit_card_match.lastgroup, credit_card_found))

    return credit_cards
