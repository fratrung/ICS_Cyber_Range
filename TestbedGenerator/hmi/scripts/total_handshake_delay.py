#!/usr/bin/env python
from pymodbus.client import ModbusTcpClient as ModbusClient
import time
import threading
import numpy as np
from scipy import stats
import sys


n=input("Enter the number of samples: ")
n=float(n)


delays = []

timeout = False
samples = 0
confidence_level = 0.95

number_of_plc_proxy = 25

total_request_for_each_plc_proxy = int(n)/int(number_of_plc_proxy)
print(total_request_for_each_plc_proxy)


print("Contacting all PLC")

for i in range(1,int(number_of_plc_proxy)+1):
    plc_address = f"172.29.0.{121 + i}"
    client =  ModbusClient(plc_address, port=502, timeout=20)
    start = time.time()
    client.connect()
    stop = time.time()
    delay = stop - start
    delays.append(delay)
    print(f"{plc_address} Handshake delay: {delay}")
    #read one coil just to test connection, but it's not measured
    r = client.read_coils(0, 1)
    client.close()
    time.sleep(0.5)

delays = []
 
time.sleep(1)
print("Start simulation..")
for i in range(1,int(number_of_plc_proxy)+1):
    plc_address = f"172.29.0.{121 + i}"
    client =  ModbusClient(plc_address, port=502, timeout=20)
    for i in range(int(total_request_for_each_plc_proxy)):
        start = time.time()
        client.connect()
        stop = time.time()
        delay = stop - start
        delays.append(delay)
        print(delay)
        #read one coil just to test connection, but it's not measured
        r = client.read_coils(0, 1)
        client.close()
        time.sleep(0.5)

mean = np.mean(delays)
std_err = np.std(delays, ddof=1) / np.sqrt(len(delays))
df = len(delays) - 1
t_critical = stats.t.ppf((1 + confidence_level) / 2, df)
margin_of_error = t_critical * std_err
delays = []
print(len(delays))
print(f"Average latency: {mean}")
print(f"Margin of error: {margin_of_error}")
    
file = f"handshake-avrg-delay.txt"
file_err = f"handshake-error.txt"

try:
    with open(file, "w") as f:
        f.write(f"{mean}\n")
    with open(file_err, "w") as f:
        f.write(f"{margin_of_error}\n")
except Exception as e:
    print(f"Failed to write to file: {e}")

client.close()
sys.exit(0)
