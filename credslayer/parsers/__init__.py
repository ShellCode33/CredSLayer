# coding: utf-8

"""
Each parser within the ``credslayer.parsers`` module will extract credentials of corresponding protocols.
For example if tshark identifies a packet to be part of the FTP, CredSLayer will automatically dispatch its analysis to
the ``ftp.py`` parser.
"""

import os
from importlib import import_module

_script_dir = os.path.dirname(os.path.abspath(__file__))
_module_names = [os.path.splitext(_file)[0] for _file in os.listdir(_script_dir) if not _file.startswith('__')]
parsers = {}

for module_name in _module_names:
    module = import_module("credslayer.parsers." + module_name)
    parsers[module_name] = module
