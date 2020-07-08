Use in your own project
=======================

CredSLayer is available in PyPI repository, you can simply add ``credslayer`` to your ``requirements.txt`` file.

The easiest way to retrieve credentials from a pcap is as follow :

.. code-block:: python

    from credslayer.manager import process_pcap

    if __name__ == "__main__":
        credentials = process_pcap("my_capture.pcap").get_list_of_all_credentials()

        for creds in credentials:
            print(creds)

I you want to perform a live capture and process credentials as they come, you can use a callback as follow :

.. code-block:: python

    from credslayer.manager import active_processing

    def process_found_credentials(credentials: Credentials):
        print("Found:", credentials)

    if __name__ == "__main__":
        active_processing("wlp2s0", callback=process_found_credentials)
