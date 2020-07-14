#!/usr/bin/python3
# coding: utf-8

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='CredSLayer',
    version='0.1.1',
    description='Extract credentials and other useful info from network captures',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="credentials security networking extraction mining wireshark tshark dissector password",
    author='ShellCode',
    author_email='shellcode33@protonmail.ch',
    url='https://github.com/ShellCode33/CredSLayer',
    packages=find_packages(),
    python_requires='>=3.5',

    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],

    install_requires=[
        "pyshark",
        "argcomplete"
    ],

    entry_points={
        "console_scripts": [
            "credslayer = credslayer.credslayer:main",
        ]
    }
)
