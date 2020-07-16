Environment setup
=================

First you must `fork the repository <https://github.com/ShellCode33/CredSLayer/fork>`_.
Then clone your personal repo and create a new branch based on develop :

.. code-block:: none

    $ git clone https://github.com/[YourUsername]/CredSLayer
    $ cd CredSLayer/
    $ git checkout -b [Choose a name] develop

To prevent any dependencies conflicts, it's recommended to create a `virtualenv <https://docs.python.org/fr/3/library/venv.html>`_.
CredSLayer supports Python 3.5 and above, so in order to make sure your code is compatible, I suggest you install this version of Python and create a virtualenv with it :

.. code-block:: none

    $ python3.5 -m venv venv
    $ source venv/bin/activate

Then install the project in "dev mode" :

.. code-block:: none

    $ pip install -e .

At this point, ``credslayer`` should be available from the command line (only when you're inside the virtualenv). The command will automatically use the latest changes you make to the code.

Once you're done with your modifications, make sure your code didn't break anything by running the unit tests:

.. code-block:: none

    $ python -m unittest tests/tests.py

If there's no failure, add, commit and push your code :

.. code-block:: none

    $ git add path/to/updated/file
    $ git commit -m "short description of your changes"
    $ git push

Then go to GitHub and create a pull request. I will review it and decide whether or not it's worth integrating it.