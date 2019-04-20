# coding: utf-8
from csl.core.session import Session


class Color(object):
    BRIGHT_BLUE = "\u001b[34;1m"
    WHITE = "\u001b[37m"
    CYAN = "\u001b[36m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    RESET = "\u001b[0m"
    BACKGROUND_RED = "\u001b[41m"


def debug(*args):
    if len(args) == 2:
        session = args[0]
        msg = args[1]
        print("{}[{} {}] {}[DEBUG]{} {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.CYAN, Color.RESET, msg))
    else:
        msg = args[0]
        print("{}[DEBUG]{} {}".format(Color.CYAN, Color.RESET, msg))


def info(*args):
    if len(args) == 2:
        session = args[0]
        msg = args[1]
        print("{}[{} {}] {}[INFO]{}  {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.GREEN, Color.RESET, msg))
    else:
        msg = args[0]
        print("{}[INFO]{} {}".format(Color.GREEN, Color.RESET, msg))


def error(msg: str):
    print("{}[ERROR]{} {}".format(Color.RED, Color.RESET, msg))


def found(session: Session, msg: str):
    print("{}[{} {}] {}{}[FOUND]{} {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.WHITE, Color.BACKGROUND_RED, Color.RESET, msg))
