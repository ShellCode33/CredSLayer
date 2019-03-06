# coding: utf-8

import base64
from typing import List
from urllib.parse import urlparse, parse_qs

from scapy.plist import PacketList
from scapy_http.http import HTTP, HTTPRequest, HTTPResponse

from ncm.core import logger
from ncm.core.utils import CredentialsList, Credentials

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


def _extract_http_requests(packets: PacketList) -> List[HTTPRequest]:
    http_requests = []

    current_request = None

    for packet in packets:

        # On ports 80 and 8080 scapy_http will have parsed packets already and HTTPRequest/Response will be available

        if HTTPRequest in packet:
            current_request = packet
            continue

        elif HTTPResponse in packet and current_request is not None:
            current_request.resp_status_code = int(getattr(packet, "Status-Line").decode().split(" ")[1])
            http_requests.append(current_request)
            current_request = None
            continue

        if not hasattr(packet, "load"):
            continue

        # However on other ports, we have to try to build the HTTP layer to see if HTTP is in use

        potential_http_packet = HTTP(packet.load)
        class_type = potential_http_packet.guess_payload_class(packet.load)

        if class_type == HTTPRequest:
            current_request = potential_http_packet

        elif class_type == HTTPResponse:
            current_request.resp_status_code = int(packet.load.decode().split(" ")[1])
            http_requests.append(current_request)
            current_request = None

    return http_requests


def analyse(packets: PacketList) -> CredentialsList:
    logger.debug("HTTP analysis...")

    all_credentials = []

    http_requests = _extract_http_requests(packets)

    for http_request in http_requests:
        requested_path = http_request.Path.decode()
        requested_url = "http://{}{}".format(http_request.Host.decode(), requested_path)
        extension = requested_url.split(".")[-1]

        if extension not in HTTP_IGNORED_EXTENSIONS:
            logger.info("URL found: '{}'".format(requested_url))

        if http_request.Method == b"POST":
            try:
                post_content = http_request.load.decode()

                if len(post_content) <= HTTP_AUTH_MAX_LOGIN_POST_LENGTH:
                    logger.info("POST data found: '{}'".format(post_content))
                    get_parameters = parse_qs(post_content)

                    username = password = None

                    for parameter in get_parameters:
                        if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                            username = get_parameters[parameter][0]
                        elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                            password = get_parameters[parameter][0]

                    all_credentials.append(Credentials(username, password))

            except UnicodeDecodeError:  # Posted data can be raw bytes (e.g. images)
                pass

        if http_request.Method == b"GET":
            get_parameters = parse_qs(urlparse(http_request.Path.decode()).query)

            username = password = None

            for parameter in get_parameters:
                if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                    username = get_parameters[parameter][0]
                elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                    password = get_parameters[parameter][0]

            all_credentials.append(Credentials(username, password))

        if http_request.Authorization is not None:
            authorization_header = http_request.Authorization.decode()
            tokens = authorization_header.split(" ")

            if len(tokens) == 2 and tokens[0] == "Basic":
                credentials = tokens[1]

                try:
                    credentials = base64.b64decode(credentials).decode()
                    colon_index = credentials.find(":")

                    if http_request.resp_status_code != 401:
                        all_credentials.append(Credentials(credentials[:colon_index], credentials[colon_index + 1:]))

                except UnicodeDecodeError:
                    continue

            else:
                logger.info("Authorization header found: '{}'".format(authorization_header))

    return all_credentials
