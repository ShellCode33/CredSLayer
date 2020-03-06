# coding: utf-8
import base64

from pyshark.packet.layer import Layer

from credslayer.core import logger
from credslayer.core.session import Session


def _fix_tshark_widechar_issue(layer) -> (str, str):
    if hasattr(layer, "authorization") and layer.authorization.startswith("NTLM "):  # HTTP header dirty fix
        ntlm_bytes = base64.b64decode(layer.authorization[5:])
        username_offset = int(layer.ntlmssp_string_offset.all_fields[1].show)
        domain_offset = int(layer.ntlmssp_string_offset.all_fields[0].show)
        username_length = int(layer.ntlmssp_string_length.all_fields[1].show)
        domain_length = int(layer.ntlmssp_string_length.all_fields[0].show)

        username = ntlm_bytes[username_offset:username_offset + username_length].replace(b"\x00", b"").decode()
        domain = ntlm_bytes[domain_offset:domain_offset + domain_length].replace(b"\x00", b"").decode()
        return username, domain

    else:  # Not able to find a fix
        logger.error("The username or domain are only 1 character long, probably because of wide characters, "
                     "investigate manually.")

        return "UNKNOWN", "UNKNOWN"


# Great resource : http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response

def analyse(session: Session, layer: Layer, ) -> bool:

    current_creds = session.credentials_being_built

    if not current_creds.is_empty() and hasattr(layer, "nt_status"):
        status = int(layer.nt_status)

        if status == 0:  # LOGON SUCCESS
            logger.found(session, "{} found: {}".format(current_creds.context["version"], current_creds.hash))
            return True
        elif status == 3221225581:  # LOGON FAILED
            session.invalidate_credentials_and_clear_session()

    if hasattr(layer, "ntlmssp_messagetype"):
        message_type = int(layer.ntlmssp_messagetype, 16)

        if message_type == 2:  # Challenge
            session["challenge"] = layer.ntlmssp_ntlmserverchallenge.replace(":", "")

        elif message_type == 3:  # Auth

            username = layer.ntlmssp_auth_username
            domain = layer.ntlmssp_auth_domain
            challenge = session["challenge"]

            if len(username) == 1 or len(domain) == 1:
                username, domain = _fix_tshark_widechar_issue(layer)

            if not challenge:
                challenge = "CHALLENGE_NOT_FOUND"

            if domain == "NULL":
                domain = ""

            if hasattr(layer, "ntlmssp_ntlmv2_response"):
                current_creds.context["version"] = "NETNTLMv2"
                proof = layer.ntlmssp_ntlmv2_response_ntproofstr
                auth_ntresponse = layer.ntlmssp_ntlmv2_response[len(proof)+1:]
                proof = proof.replace(":", "")
                auth_ntresponse = auth_ntresponse.replace(":", "")
                current_creds.hash = "{}::{}:{}:{}:{}".format(username, domain, session["challenge"], proof, auth_ntresponse)

            elif hasattr(layer, "ntlmssp_ntlmclientchallenge"):
                current_creds.context["version"] = "NETNTLMv1"
                auth_ntresponse = layer.ntlmssp_auth_ntresponse.replace(":", "")
                client_challenge = layer.ntlmssp_ntlmclientchallenge.replace(":", "").ljust(48, "0")
                current_creds.hash = "{}::{}:{}:{}:{}".format(username, domain, client_challenge, auth_ntresponse, challenge)

            else:  # Unsupported NTLM format, investigate ? Found a pcap w/o ntlm client challenge field
                session.invalidate_credentials_and_clear_session()

    return False
