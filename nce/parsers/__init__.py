# coding: utf-8

import os
from importlib import import_module

_script_dir = os.path.dirname(os.path.abspath(__file__))
_modules = [os.path.splitext(_file)[0] for _file in os.listdir(_script_dir) if not _file.startswith('__')]
parsers = []

for module in _modules:
    module = import_module("nce.parsers." + module)
    parsers.append(module)
