# This docker file is only used as a test environment
# it will run unit tests with the expected system configuration

FROM ubuntu:18.04

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark python3-pip

COPY . /app
WORKDIR /app

RUN pip3 install -r requirements.txt
CMD python3 -m unittest tests/tests.py