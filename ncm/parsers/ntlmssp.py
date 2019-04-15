# coding: utf-8

from pyshark.packet.layer import Layer

from ncm.core.session import Session
from ncm.core.utils import Credentials


def analyse(session: Session, layer: Layer) -> Credentials:

    if hasattr(layer, "ntlmssp_auth_username") and layer.ntlmssp_auth_username != "NULL":
        print(layer.ntlmssp_auth_username)
        print(layer.ntlmssp_auth_domain)
        print(layer.ntlmssp_auth_ntresponse)
