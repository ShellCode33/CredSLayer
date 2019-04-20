# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    if hasattr(layer, "ntlmssp_auth_username") and layer.ntlmssp_auth_username != "NULL":
        print(layer.ntlmssp_auth_username)
        print(layer.ntlmssp_auth_domain)
        print(layer.ntlmssp_auth_ntresponse)

    return False
