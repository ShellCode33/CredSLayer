# coding: utf-8

import base64
from urllib.parse import parse_qs
from pyshark.packet.packet import Packet
from ncm.core import logger
from ncm.core.session import SessionList
from ncm.core.utils import Credentials

HTTP_IGNORED_EXTENSIONS = ["css", "ico", "png", "jpg", "jpeg", "gif"]
HTTP_METHODS = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]

HTTP_AUTH_MAX_LOGIN_POST_LENGTH = 500  # We ignore every posted content exceeding that length to prevent false positives
HTTP_AUTH_POTENTIAL_USERNAMES = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                                 'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname',
                                 'loginname', 'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid',
                                 'id', 'user_id', 'screename', 'uname', 'ulogin', 'acctname', 'account', 'member',
                                 'mailaddress', 'membername', 'login_username', 'login_email', 'loginusername',
                                 'loginemail', 'uin', 'sign-in', 'j_username']

HTTP_AUTH_POTENTIAL_PASSWORDS = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password',
                                 'sessionpassword', 'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword',
                                 'pwd', 'upassword', 'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd',
                                 'j_password']

sessions = SessionList()


def analyse(packet: Packet) -> Credentials:

    session = sessions.get_session_of(packet)

    if hasattr(packet["http"], "request_uri"):  # Process requests only, we don't care about responses
        extension = packet["http"].request_uri.split(".")[-1]

        if extension not in HTTP_IGNORED_EXTENSIONS:
            logger.info("URL found: '{}'".format(packet["http"].request_full_uri))
        else:
            return None

        if hasattr(packet["http"], "authorization"):
            tokens = packet["http"].authorization.split(" ")

            if len(tokens) == 2 and tokens[0] == "Basic":
                try:
                    credentials = base64.b64decode(tokens[1]).decode()
                    colon_index = credentials.find(":")
                    session["username"] = credentials[:colon_index]
                    session["password"] = credentials[colon_index+1:]
                    session["authorization_header_uri"] = packet["http"].request_full_uri
                except UnicodeDecodeError:
                    logger.error("HTTP Basic auth failed: " + tokens)
                    return None

            else:
                logger.info("Authorization header found: '{}'".format(packet["http"].authorization))

        if hasattr(packet["http"], "request_uri_query"):
            get_parameters = parse_qs(packet["http"].request_uri_query)

            username = password = None

            for parameter in get_parameters:
                if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                    username = get_parameters[parameter][0]
                elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                    password = get_parameters[parameter][0]

            logger.found("HTTP", "credentials found: {} -- {}".format(username, password))
            return Credentials(username, password)

        elif hasattr(packet["http"], "file_data"):  # POST requests
            post_content = packet["http"].file_data

            if len(post_content) <= HTTP_AUTH_MAX_LOGIN_POST_LENGTH:
                logger.info("POST data found: '{}'".format(post_content))
                post_parameters = parse_qs(post_content)

                username = password = None

                for parameter in post_parameters:
                    if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                        username = post_parameters[parameter][0]
                    elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                        password = post_parameters[parameter][0]

                logger.found("HTTP", "credentials found: {} -- {}".format(username, password))
                return Credentials(username, password)

    elif hasattr(packet["http"], "response_for_uri"):
        if session["authorization_header_uri"] == packet["http"].response_for_uri and packet["http"].response_code != "401":
            sessions.remove(session)
            logger.found("HTTP", "credentials found: {} -- {}".format(session["username"], session["password"]))
            return Credentials(session["username"], session["password"])
