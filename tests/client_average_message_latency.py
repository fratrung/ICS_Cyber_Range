#!/usr/bin/env python
""" 
This program is used to measure the average message latency by varying the number of requests per second.
"""
from pymodbus.client import ModbusTcpClient as ModbusClient
import time
import threading
import sys
import scipy.stats as stats
import numpy as np

client = ModbusClient('10.0.2.5', port=502, timeout=20)

unit=255

# take n as input
n=input("Enter the number of samples: ")
n=float(n)


delays = []

timeout = False
samples = 0
confidence_level = 0.95



def read_coils():
    global samples
    global client
    samples+=1
    t = threading.Timer(1/n, read_coils)
    t.daemon = True
    t.start()
    try:
        start_time = time.time()
        rr = client.read_coils(0, 1, unit=unit)
        end_time = time.time()
        if rr.isError():
            print(f"Error: {rr}")
        else:
            latency = end_time - start_time
            if samples > 5*n:
                delays.append(latency)
            print(latency)
    except Exception as e:
        print(f"Exception occurred: {e}")


start_time = time.time()
rr = client.read_coils(0, 1, unit=unit)
end_time = time.time()
latency = end_time - start_time
print(latency)


print("Starting timer")
start = time.time()
read_coils()

while time.time() - start < 105:
    pass


mean = np.mean(delays)
std_err = np.std(delays, ddof=1) / np.sqrt(len(delays))
df = len(delays) - 1
t_critical = stats.t.ppf((1 + confidence_level) / 2, df)
margin_of_error = t_critical * std_err

print(len(delays))
print(f"Average latency: {mean}")
print(f"Margin of error: {margin_of_error}")

try:
    with open("chacha20_avrg.txt", "a") as f:
        f.write(f"{mean} ")
    with open("chacha20_error.txt", "a") as f:
        f.write(f"{margin_of_error} ")
except Exception as e:
    print(f"Failed to write to file: {e}")
client.close()
sys.exit(0)


"""
#Program alternative to test plc's program

# Get the initial state
start_time = time.time()
rr = client.read_coils(0, 1, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("Initial LED output: " + str(rr.getBit(0)))
print("Request latency: " + str(latency))


start_time = time.time()
client.write_coil(1, True, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("Pressed PB1 - turn on LED")
print("Request latency: " + str(latency))


start_time = time.time()
client.write_coil(1, False, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("Unpressed PB1")
print("Request latency: " + str(latency))


start_time = time.time()
rr = client.read_coils(0, 1, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("LED output after pressing PB1: " + str(rr.getBit(0)))
print("Request latency: " + str(latency))


start_time = time.time()
client.write_coil(2, True, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("Pressed PB2 - reset")
print("Request latency: " + str(latency))


start_time = time.time()
client.write_coil(2, False, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("Unpressed PB2")
print("Request latency: " + str(latency))


start_time = time.time()
rr = client.read_coils(0, 1, unit=unit)
end_time = time.time()
latency = end_time - start_time
print("LED output after pressing PB2 (reset): " + str(rr.getBit(0)))
print("Request latency: " + str(latency))


client.close()
"""
