# coding: utf-8

import time
from threading import Thread, Lock
from typing import List, Tuple

from pyshark.packet.packet import Packet

from credslayer.core.utils import Credentials


_running_threads = []  # type: List[Thread]
_keep_threads_alive_lock = Lock()
_keep_threads_alive_lock.acquire()  # Thread will stay alive as long as the lock is acquired


def stop_managed_sessions():
    """
    Will stop threads managing sessions.
    """
    _keep_threads_alive_lock.release()

    for thread in _running_threads:
        thread.join()

    _running_threads.clear()


class SessionException(Exception):
    """
    Exception related to the `Session` class.
    """
    pass


class Session(dict):
    """
    A `Session` object represents an exchange of packets between two parties. TCP and UDP communication are not
    considered in the same way. Put simply a session is a way of grouping packets together in order to create some
    context. CredSLayer identifies a TCP exchange based on the IP addresses and port of each party.
    Here's an example of its string representation : "192.168.1.42:42000 <-> 42.42.42.42:443"
    This representation is the identity of a session, it's what makes it unique. On the other hand, UDP being a
    stateless protocol, its source port cannot be relied on because it is always different. That's why CredSLayer
    builds UDP sessions based on the source address and the destination address and port.
    Here's a example of its string representation : "192.168.1.42 <-> 42.42.42.42:53"

    Attributes
    ----------
    protocol : str
        The identified protocol, at first it will either be TCP or UDP, but it can be updated at any time to be more
        specific about what the protocol being analysed really is.

    credentials_being_built : Credentials
        Credentials going over the wire are often split into multiple packets (e.g. the username in a first packet,
        then the password in a second one), this is why each `Session` object has an instance of the `Credentials`
        object which will hold all the information being gathered to compose the credentials over time.

    credentials_list : List[Credentials]
        A list of credentials found so far in the session. Most of the time it will only hold a single `Credentials`
        instance.

    Raises
    ------
    SessionException
        This exception will occur if the session relative to a packet cannot be  built (mostly because the packet
        isn't TCP or UDP based).
    """

    INACTIVE_SESSION_DELAY = 10  # in seconds
    creds_found_callback = None

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

    def __repr__(self):
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
        """
        At some point, a CredSLayer parser should be able to identify that a successful authentication has been made,
        to tell CredSLayer the `credentials_being_built` are valid, this method must be called. This will create a new
        instance of `Credentials` in order to build new potential incoming credentials of the same session.
        """
        self.credentials_list.append(self.credentials_being_built)

        if Session.creds_found_callback:
            Session.creds_found_callback(self.credentials_being_built)

        self.credentials_being_built = Credentials()

    def invalidate_credentials_and_clear_session(self):
        """
        At some point, a CredSLayer parser should be able to identify that an unsuccessful authentication has been made,
        to tell CredSLayer the `credentials_being_built` are invalid and what it contains must be discarded, this method
        must be called. This will create a new instance of `Credentials` in order to build new potential incoming
        credentials of the same session.
        """
        self.clear()
        self.credentials_being_built = Credentials()

    def should_be_deleted(self):
        return time.time() - self._last_seen_time > Session.INACTIVE_SESSION_DELAY


class SessionsManager(List[Session]):
    """
    The `SessionsManager` object is basically a list of `Session` objects, it will most likely be created once and be
    used during the whole program's lifespan. It ensures the uniqueness of a `Session`, can delete outdated sessions and
    enables the developer to retrieve data about all the sessions at once (e.g. all credentials found so far).
    """

    def __init__(self, remove_outdated=False):
        """
        Parameters
        ----------
        remove_outdated : bool
            Whether old sessions should be removed from memory after a given time or not. This prevents RAM overloading.
            Especially useful when listening indefinitely on an interface.
        """
        super().__init__()

        if remove_outdated:
            thread = Thread(target=self._manage)
            _running_threads.append(thread)
            thread.start()

    def get_session_of(self, packet: Packet) -> Session:
        """
        Parameters
        ----------
        packet : Packet
            The packet from which the `Session` object will be created or retrieved.

        Returns
        -------
        Session
            This method returns the `Session` object associated to the given packet.

        """
        session = Session(packet)

        try:
            session_index = self.index(session)
            session = self[session_index]
        except ValueError:
            self.append(session)

        return session

    def _manage(self):
        """
        This function is an almost-infinite loop running in a separate thread which deletes old sessions that will
        probably not be used anymore. This is here mostly to prevent RAM overloading.
        """
        while not _keep_threads_alive_lock.acquire(timeout=Session.INACTIVE_SESSION_DELAY):
            self._remove_outdated_sessions()

    def _remove_outdated_sessions(self):
        """
        Deletes unused `Session` objects based on how long no activity has been seen.
        """
        sessions_to_remove = [session for session in self if session.should_be_deleted()]

        for session in sessions_to_remove:
            self.remove(session)

    def get_remaining_content(self) -> List[Tuple[Session, Credentials]]:
        """
        Sometimes CredSLayer parsers are not able to tell if the provided credentials were valid or not, the `Session`
        instance still conserves those, and this method is here to return what's remaining in all sessions.

        Returns
        -------
        List[Tuple[Session, Credentials]]
            Each entry is a tuple of the `Session` instance and the remaining `credentials_being_built`.
        """
        return [(session, session.credentials_being_built) for session in self if session.credentials_being_built]

    def get_list_of_all_credentials(self) -> List[Credentials]:
        """
        Returns
        -------
        List[Credentials]
            A list of all valid `Credentials` instances built during the whole `SessionManager` lifespan.
        """
        all_credentials = []

        for session in self:
            all_credentials += session.credentials_list

        return all_credentials
