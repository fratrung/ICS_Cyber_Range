FROM ubuntu:20.04

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get -yq install net-tools inetutils-ping iproute2 libnfnetlink-dev libnetfilter-queue-dev iptables
RUN apt-get -y install python3-pip
RUN pip install pymodbus scapy pycryptodome requests



