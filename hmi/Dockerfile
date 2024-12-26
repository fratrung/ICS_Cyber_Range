FROM ubuntu:20.04

RUN apt-get update
RUN apt-get -y install net-tools inetutils-ping iproute2 iperf3
RUN apt-get -y install python3-pip
RUN pip install pymodbus scapy pycryptodome
RUN pip install modbus-tk pySerial twisted

