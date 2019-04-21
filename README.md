# CredSLayer

![alt python_version](https://img.shields.io/badge/python-3.5+-informational.svg)
![alt tests_coverage](https://img.shields.io/badge/tests%20coverage-94%25-success.svg)

You thought PCredz was good ? Net-creds even better ? Try this out, you'll be surprised !

CredSLayer goal is to look for credentials and other useful stuff in network captures. Two modes are available, pcap scanning and active processing. The latest listens for packets on a chosen interface and dynamically extracts everything it can.

This tool is really helpful if you're a pentester or if you want to scan your own network to see if anything critical is sent over. 

The code is based on [pyshark](https://github.com/KimiNewt/pyshark). It basically gives an access to Wireshark dissectors, resulting in an incredible amount of supported protocols. 

# Features

Right now, CredSLayer supports the following protocols:
* FTP
* SMTP / IMAP / POP3
* Telnet
* HTTP
* LDAP
* HTTP
* SNMP
* MySQL
* NTLMSSP

It is also able to look for email addresses and credit card numbers.

# Install

```
$ git clone https://github.com/ShellCode33/CredSLayer.git
$ cd CredSLayer/
$ python3 -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python CredSLayer.py -h
```

pip package coming soon...

# Usage

```
$ python CredSLayer.py -h                                  
usage: CredSLayer.py [-h] [-l INTERFACE] [-s {enable,disable}]
                     [pcapfiles [pcapfiles ...]]

Helps you find credentials and other interesting stuff in network captures

positional arguments:
  pcapfiles             pcap files you want to analyse.

optional arguments:
  -h, --help            show this help message and exit
  -l INTERFACE, --listen INTERFACE
                        start active processing on specified interface
  -s {enable,disable}, --string-inspection {enable,disable}
                        let you specify if you want to look for interesting
                        strings (email addresses, credit cards, ...) in
                        network captures. Pretty heavy on the CPU. Enabled by
                        default on pcap files, disabled on live captures.
```

# Get involved

Thanks to Wireshark dissectors, it's really easy to write new protocols support, you're welcome to contribute !

Contributing doesn't necessarily mean writing code. You can simply contribute by opening new issues on Github if you spot any bug or if you would like to see something added to the tool.

CredSLayer automatically dispatch packets to the appropriate file, for example if a LDAP packet is received, CredSLayer will send the `LDAP` layer to the `analyse` function inside `ldap.py`.

So if you want to support a new protocol, all you have to do is create a new file **named after the layer name** you want to parse. You can find the layer name by looking at the `Protocol` column in Wireshark.

There's one exception to that. If the protocol you want to extract credentials from can be embedded in other protocol, the procedure is a bit more complex (you can look at `ntlmssp.py` and `manager.py` to understand the mechanisms involved).

Otherwise, to create a simple module, there are a few things you need to know :
- The `analyse()` function's parameter `layer` is simply the layer you want to analyse, it contains everything the Wireshark dissector were able to find. 
- The `analyse()` function's parameter `session` is a dictionary that enables you to have a context between the packets, it can keep stuff you found in a packet so you can access those variables to analyse the packets that follow.
- The `session` has 2 attributes you must know of. The first one is `credentials_being_built`, it's the `Credentials` object you must fill when you find something interesting (username, password, hash, etc). The second attribute is `credentials_list`, it's a list of `Credentials` objects and it is automatically filled with `credentials_being_built` when the `analyse()` function returns true. But in some cases (you can find one in `http.py`), you might want to fill that list manually.   
- You must ensure the authentication was successful before logging any credentials. The credentials being built but not validated will be automatically logged as `info` by CredSLayer's "garbage collector".
- If at some point of your processing you realise the credentials being built aren't valid, you must call `session.invalidate_credentials_and_clear_session()`.    

Good luck ! If you need help to understand something, feel free to contact me : shellcode33{at}protonmail.ch  

# Credits

* Wireshark for their [pcaps](https://wiki.wireshark.org/SampleCaptures)

* [moloch](https://github.com/aol/moloch) for their [pcaps](https://github.com/aol/moloch/tree/master/tests/pcap)

* [asecuritysite](https://asecuritysite.com) for their [pcaps](https://asecuritysite.com/forensics/pcap)
