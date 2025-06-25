FROM ubuntu:20.04

RUN sed -i 's|http://security.ubuntu.com|http://archive.ubuntu.com|g' /etc/apt/sources.list
RUN apt-get update
RUN apt-get -y install net-tools inetutils-ping iproute2 iperf3
RUN apt-get -y install python3-pip
RUN apt-get install nano 
RUN pip install pymodbus scapy pycryptodome
RUN pip install modbus-tk pySerial twisted numpy scipy

