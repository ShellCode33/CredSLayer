# coding: utf-8

import os
from importlib import import_module

_script_dir = os.path.dirname(os.path.abspath(__file__))
_module_names = [os.path.splitext(_file)[0] for _file in os.listdir(_script_dir) if not _file.startswith('__')]
parsers = {}

for module_name in _module_names:
    module = import_module("csl.parsers." + module_name)
    parsers[module_name] = module
