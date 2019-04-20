# coding: utf-8

import base64
from urllib.parse import parse_qs

from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session

HTTP_IGNORED_EXTENSIONS = ["css", "ico", "png", "jpg", "jpeg", "gif", "js"]
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


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "request_uri"):

        extension = layer.request_uri.split(".")[-1]

        if extension in HTTP_IGNORED_EXTENSIONS:
            return False

        if layer.request_full_uri.startswith("http://ocsp."):  # Ignore Certificate Status Protocol
            return False

        if hasattr(layer, "authorization"):
            tokens = layer.authorization.split(" ")

            if len(tokens) == 2 and tokens[0] == "Basic":
                try:
                    credentials = base64.b64decode(tokens[1]).decode()
                    colon_index = credentials.find(":")
                    current_creds.username = credentials[:colon_index]
                    current_creds.password = credentials[colon_index+1:]
                    session["authorization_header_uri"] = layer.request_full_uri
                except UnicodeDecodeError:
                    logger.error("HTTP Basic auth failed: " + tokens)

            else:
                logger.info(session, "Authorization header found: '{}'".format(layer.authorization))

        # POST parameters
        elif hasattr(layer, "file_data"):
            post_content = layer.file_data

            if len(post_content) <= HTTP_AUTH_MAX_LOGIN_POST_LENGTH:
                logger.info(session, "POST data found: '{}'".format(post_content))
                post_parameters = parse_qs(post_content)

                session.invalidate_credentials_and_clear_session()
                current_creds = session.credentials_being_built

                current_creds.context["Method"] = "POST"
                current_creds.context["URL"] = layer.request_full_uri

                for parameter in post_parameters:
                    if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                        current_creds.username = post_parameters[parameter][0]
                    elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                        current_creds.password = post_parameters[parameter][0]

                if current_creds.username:
                    logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                    return True

        # GET parameters
        elif hasattr(layer, "request_uri_query"):
            get_parameters = parse_qs(layer.request_uri_query)

            session.invalidate_credentials_and_clear_session()
            current_creds = session.credentials_being_built

            current_creds.context["Method"] = "GET"
            current_creds.context["URL"] = layer.request_full_uri

            for parameter in get_parameters:
                if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                    current_creds.username = get_parameters[parameter][0]
                elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                    current_creds.password = get_parameters[parameter][0]

            if current_creds.username:
                logger.found(session, "credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                logger.info(session, "context: " + str(current_creds.context))
                return True

    elif hasattr(layer, "response_for_uri"):

        if session["authorization_header_uri"] == layer.response_for_uri:

            # If auth failed + prevent duplicates
            if layer.response_code == "401" or current_creds in session.credentials_list:
                session.invalidate_credentials_and_clear_session()

            else:
                logger.found(session, "basic auth credentials found: {} -- {}".format(current_creds.username, current_creds.password))
                return True

    return False
