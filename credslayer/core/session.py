# coding: utf-8

import time
from threading import Thread
from typing import List, Tuple

from pyshark.packet.packet import Packet

from credslayer.core.utils import Credentials


_keep_threads_alive = True
_running_threads = []  # type: List[Thread]


def stop_managed_sessions():
    global _keep_threads_alive
    _keep_threads_alive = False

    for thread in _running_threads:
        thread.join()

    _running_threads.clear()


class SessionException(Exception):
    pass


class Session(dict):

    INACTIVE_SESSION_DELAY = 10  # in seconds

    def __init__(self, packet: Packet):
        super().__init__()

        if "ipv6" in packet:
            ip_type = "ipv6"
            proto_id = int(getattr(packet, ip_type).nxt)
        elif "ip" in packet:
            ip_type = "ip"
            proto_id = int(getattr(packet, ip_type).proto)
        else:
            raise SessionException("IP layer not found")

        if proto_id == 6:
            self.protocol = "tcp"
            src = "{}:{}".format(packet[ip_type].src, packet.tcp.srcport)
            dst = "{}:{}".format(packet[ip_type].dst, packet.tcp.dstport)
        elif proto_id == 17:
            self.protocol = "udp"
            # We don't track UDP "sessions" using port because client's port changes every time...
            src = packet[ip_type].src
            dst = packet[ip_type].dst
        else:
            raise SessionException("Unsupported protocol id: " + str(proto_id))

        if packet[self.protocol].srcport == packet[self.protocol].dstport:
            # Alphabetic ordering on IP addresses if ports are the same
            if packet[ip_type].src < packet[ip_type].dst:
                self._session_string_representation = src + " <-> " + dst
            else:
                self._session_string_representation = dst + " <-> " + src

        # Ordering based on port number
        elif int(packet[self.protocol].srcport) > int(packet[self.protocol].dstport):
            self._session_string_representation = src + " <-> " + dst
        else:
            self._session_string_representation = dst + " <-> " + src

        self._session_identifier = "{} {}".format(self.protocol.upper(), self._session_string_representation)
        self._last_seen_time = time.time()
        self.credentials_being_built = Credentials()
        self.credentials_list = []  # type: List[Credentials]

    def __eq__(self, other):
        if isinstance(other, Session):
            return self._session_identifier == other._session_identifier
        elif isinstance(other, str):
            return self._session_identifier == other
        else:
            raise ValueError("Can't compare session with something else than a session or a string")

    def __str__(self):
        return self._session_string_representation

    def __setitem__(self, name, value):
        super().__setitem__(name, value)
        self._last_seen_time = time.time()

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except KeyError:
            return None

    def validate_credentials(self):
        self.credentials_list.append(self.credentials_being_built)
        self.credentials_being_built = Credentials()

    def invalidate_credentials_and_clear_session(self):
        self.clear()
        self.credentials_being_built = Credentials()

    def should_be_deleted(self):
        return time.time() - self._last_seen_time > Session.INACTIVE_SESSION_DELAY


class SessionsManager(List[Session]):

    def __init__(self, remove_outdated=False):
        super().__init__()

        if remove_outdated:
            thread = Thread(target=self._manage)
            _running_threads.append(thread)
            thread.start()

    def get_session_of(self, packet: Packet) -> Session:
        session = Session(packet)

        try:
            session_index = self.index(session)
            session = self[session_index]
        except ValueError:
            self.append(session)

        return session

    def _manage(self):

        while True:

            for i in range(Session.INACTIVE_SESSION_DELAY):
                time.sleep(1)

                if not _keep_threads_alive:
                    return

            self._remove_outdated_sessions()

    def _remove_outdated_sessions(self):
        sessions_to_remove = [session for session in self if session.should_be_deleted()]

        for session in sessions_to_remove:
            self.remove(session)

    def get_remaining_content(self) -> List[Tuple[Session, Credentials]]:
        return [(session, session.credentials_being_built) for session in self if session.credentials_being_built]

    def get_list_of_all_credentials(self) -> List[Credentials]:
        all_credentials = []

        for session in self:
            all_credentials += session.credentials_list

        return all_credentials

    def __str__(self):
        return str([str(session) for session in self])
