Sessions
========

CredSLayer's sessions is probably the most important concept, it helps you create a context between loads of packets you "receive".
It will hold credentials you find and enables parsers to keep variables across per-packet analysis.

For example in telnet, data are transmitted line by line, and sometimes character by character.
So the parser gathers those pieces of information and store them in a session variable that will be available to further packets belonging to the same session :

.. code-block:: python

    session["data_being_built"] += data

The lines that follow are directly taken from the code's documentation and explain more in depth how sessions work.

.. automodule:: credslayer.core.session
    :members: