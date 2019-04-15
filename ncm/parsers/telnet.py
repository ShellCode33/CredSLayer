# coding: utf-8
from pyshark.packet.layer import Layer

from ncm.core import logger
from ncm.core.session import Session
from ncm.core.utils import Credentials

POTENTIAL_USERNAME_ASK = ["login:", "username:", "user:", "name:"]
POTENTIAL_AUTH_SUCCESS = ["last login", "welcome"]


def _is_username_duplicated(username):
    """
    Detects if the username has been duplicated because of telnet's echo mode.
    Duplicated username example : aaddmmiinn
    Prone to false positives, but very unlikely. Who uses usernames such as the one above ?..
    We could look for echo mode in telnet protocol, but it could be missing from the capture.
    """

    if len(username) % 2 == 1:
        return False

    for i in range(0, len(username), 2):
        if username[i] != username[i+1]:
            return False

    return True


def analyse(session: Session, layer: Layer) -> Credentials:

    if not hasattr(layer, "data"):
        return None

    if session["data_being_built"] is None:
        session["data_being_built"] = ""
        session["user_being_built"] = session["pass_being_built"] = False

    # Sometimes tshark returns multiple Data fields
    data_fields = layer.data.all_fields

    for data in data_fields:
        try:
            data = data.binary_value.decode()
        except UnicodeDecodeError:
            continue

        lowered_data = data.lower()

        if lowered_data.strip() in POTENTIAL_USERNAME_ASK:
            session["user_being_built"] = True

        elif lowered_data.strip() == "password:":
            session["pass_being_built"] = True

        elif session["password"]:
            for auth_success_msg in POTENTIAL_AUTH_SUCCESS:
                if auth_success_msg in lowered_data:
                    logger.found("TELNET", "credentials found: {} -- {}".format(session["username"], session["password"]))
                    return Credentials(session["username"], session["password"])

        else:
            session["data_being_built"] += data

            if "\r" in session["data_being_built"] or "\n" in session["data_being_built"]:
                data_being_built = session["data_being_built"].replace("\r", "")\
                                                                         .replace("\n", "")\
                                                                         .replace("\x00", "")

                if session["user_being_built"]:
                    username = data_being_built

                    if _is_username_duplicated(username):
                        username = "".join([username[i] for i in range(0, len(username), 2)])

                    session["username"] = username
                    session["user_being_built"] = False

                elif session["pass_being_built"]:
                    session["password"] = data_being_built
                    session["pass_being_built"] = False

                session["data_being_built"] = ""
