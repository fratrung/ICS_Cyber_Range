#!/usr/bin/env python
from pymodbus.client import ModbusTcpClient as ModbusClient
import time
import threading
import numpy as np
from scipy import stats
import sys



client = ModbusClient('172.29.0.123', port=502, timeout=20)

unit=255

# take n as input
n=input("Enter the number of samples: ")
n=float(n)


delays = []

timeout = False
samples = 0
confidence_level = 0.95


for i in range(int(n)):

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

print(len(delays))
print(f"Average latency: {mean}")
print(f"Margin of error: {margin_of_error}")


try:
    with open("handshake_avrg.txt", "a") as f:
        f.write(f"{mean} ")
    with open("handshake_error.txt", "a") as f:
        f.write(f"{margin_of_error} ")
except Exception as e:
    print(f"Failed to write to file: {e}")
client.close()
sys.exit(0)


