# coding: utf-8

import time
from pyshark.packet.packet import Packet


class Session(object):

    INACTIVE_SESSION_DELAY = 10  # in seconds

    _last_seen_time = None
    name = None

    def __init__(self, packet: Packet):
        proto_id = int(packet.ip.proto)

        if proto_id == 6:
            proto = "tcp"
            src = "{}:{}".format(packet.ip.src, packet.tcp.srcport)
            dst = "{}:{}".format(packet.ip.dst, packet.tcp.dstport)
        elif proto_id == 17:
            proto = "udp"
            # We don't track UDP "sessions" using port because client's port changes every time...
            src = packet.ip.src
            dst = packet.ip.dst
        else:
            raise Exception("Unsupported protocol id: " + str(proto_id))

        if src < dst:
            session_name = src + " | " + dst
        else:
            session_name = dst + " | " + src

        self.name = "{} {}".format(proto.upper(), session_name)

    def __eq__(self, other):
        if isinstance(other, Session):
            return self.name == other.name
        elif isinstance(other, str):
            return self.name == other
        else:
            raise ValueError("Can't compare session with something else than a session or a string")

    def __str__(self):
        return self.name

    def __setitem__(self, name, value):
        setattr(self, name, value)
        _last_seen_time = time.time()

    def __getitem__(self, name):
        return getattr(self, name, None)

    def should_be_deleted(self):
        return time.time() - self._last_seen_time > Session.INACTIVE_SESSION_DELAY


class SessionList(list):

    def get_session_of(self, packet: Packet) -> Session:
        session = Session(packet)

        try:
            session_index = self.index(session)
            session = self[session_index]
        except ValueError:
            self.append(session)

        return session

    def remove_outdated_sessions(self):
        sessions_to_remove = [session for session in self if session.should_be_deleted()]

        for session in sessions_to_remove:
            self.remove(session)

    def __str__(self):
        return str([str(session) for session in self])