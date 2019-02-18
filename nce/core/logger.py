# coding: utf-8


class Color(object):
    BRIGHT_BLUE = "\u001b[34;1m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    RESET = "\u001b[0m"


def debug(msg):
    print("{}[DEBUG]{} {}".format(Color.BRIGHT_BLUE, Color.RESET, msg))


def info(msg):
    print("{}[INFO]{}  {}".format(Color.GREEN, Color.RESET, msg))


def error(msg):
    print("{}[ERROR]{} {}".format(Color.RED, Color.RESET, msg))
