# coding: utf-8


class Color(object):
    BRIGHT_BLUE = "\u001b[34;1m"
    WHITE = "\u001b[37m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    RESET = "\u001b[0m"
    BACKGROUND_RED = "\u001b[41m"


def debug(msg):
    print("{}[DEBUG]{} {}".format(Color.BRIGHT_BLUE, Color.RESET, msg))


def info(msg):
    print("{}[INFO]{}  {}".format(Color.GREEN, Color.RESET, msg))


def error(msg):
    print("{}[ERROR]{} {}".format(Color.RED, Color.RESET, msg))


def found(type, username, password):
    if username is None:
        print("{}{}[FOUND]{} {} password found: {}".format(Color.WHITE, Color.BACKGROUND_RED,
                                                           Color.RESET, type.upper(), password))
    elif password is None:
        print("{}{}[FOUND]{} {} username found: {}".format(Color.WHITE, Color.BACKGROUND_RED,
                                                           Color.RESET, type.upper(), username))
    else:
        print("{}{}[FOUND]{} {} credentials found: {} -- {}".format(Color.WHITE, Color.BACKGROUND_RED,
                                                                    Color.RESET, type.upper(), username, password))
