# coding: utf-8
from pyshark.packet.layer import Layer

from credslayer.core import logger
from credslayer.core.session import Session

POTENTIAL_USERNAME_ASK = ["login:", "username:", "user:", "name:"]
POTENTIAL_AUTH_SUCCESS = ["last login", "welcome"]
POTENTIAL_AUTH_ERROR = ["incorrect", "error"]


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


def analyse(session: Session, layer: Layer) -> bool:

    if not hasattr(layer, "data"):
        return False

    current_creds = session.credentials_being_built

    # Sometimes tshark returns multiple Data fields
    data_fields = layer.data.all_fields

    for data in data_fields:

        if session["data_being_built"] is None:
            session["data_being_built"] = ""
            session["user_being_built"] = session["pass_being_built"] = False

        try:
            data = data.binary_value.decode()
        except UnicodeDecodeError:
            continue

        lowered_data = data.lower().strip()

        for username_ask in POTENTIAL_USERNAME_ASK:
            if lowered_data.endswith(username_ask):
                session["user_being_built"] = True
                break

        else:  # Yes for loops have elses ;)
            if lowered_data.endswith("password:"):
                session["pass_being_built"] = True

            elif current_creds.password:
                for auth_success_msg in POTENTIAL_AUTH_SUCCESS:
                    if auth_success_msg in lowered_data:
                        logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                        return True

                for auth_error_msg in POTENTIAL_AUTH_ERROR:
                    if auth_error_msg in lowered_data:
                        session.invalidate_credentials_and_clear_session()

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

                        current_creds.username = username
                        session["user_being_built"] = False

                    elif session["pass_being_built"]:
                        current_creds.password = data_being_built
                        session["pass_being_built"] = False

                    session["data_being_built"] = ""

    return False
