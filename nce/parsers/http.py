# coding: utf-8

import base64
from typing import List

from scapy.plist import PacketList
from scapy_http.http import HTTP, HTTPRequest, HTTPResponse

from nce.core import logger
from nce.core.utils import CredentialsList, Credentials

HTTP_IGNORED_EXTENSIONS = ["css", "ico", "png", "jpg", "jpeg", "gif"]
HTTP_METHODS = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]


def _extract_http_requests(packets: PacketList) -> List[HTTPRequest]:
    http_requests = []

    current_request = None

    for packet in packets:

        # On ports 80 and 8080 scapy_http will have parsed packets already and HTTPRequest/Response will be available

        if HTTPRequest in packet:
            current_request = packet
            continue

        elif HTTPResponse in packet and current_request is not None:
            current_request.status_code = int(getattr(packet, "Status-Line").decode().split(" ")[1])
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
            current_request.status_code = int(packet.load.decode().split(" ")[1])
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
                logger.info("POST data found: '{}'".format(post_content))
                # TODO: look for credentials in POST data
            except UnicodeDecodeError:  # Posted data can be raw bytes (e.g. images)
                pass

        # TODO: look for credentials in GET request

        if http_request.Authorization is not None:
            authorization_header = http_request.Authorization.decode()
            tokens = authorization_header.split(" ")

            if len(tokens) == 2 and tokens[0] == "Basic":
                credentials = tokens[1]

                try:
                    credentials = base64.b64decode(credentials).decode()
                    colon_index = credentials.find(":")

                    if http_request.status_code != 401:
                        all_credentials.append(Credentials(credentials[:colon_index], credentials[colon_index + 1:]))

                except UnicodeDecodeError:
                    continue

            else:
                logger.info("Authorization header found: '{}'".format(authorization_header))

    return all_credentials
