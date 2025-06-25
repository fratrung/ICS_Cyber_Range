import sys 
import time
import numpy as np
from scipy import stats 
from pymodbus.client import ModbusTcpClient as ModbusClient

def read_coil_from_PLC(plc_ip_address,samples):
    client = ModbusClient(plc_ip_address, port=502, timeout=20)
    unit = 255
    client.connect()
    delays = []
    confidence_level = 0.95
    for i in range(0,samples):
        start_time = time.time()
        rr = client.read_coils(0,1, unit=unit)
        end_time = time.time()
        latency = end_time -start_time
        delays.append(latency)
        print("Initial LED output: " + str(rr.getBit(0)))
        print("Request latency: " + str(latency))
        time.sleep(0.100)
        
    mean = np.mean(delays)
    std_err = np.std(delays, ddof=1) / np.sqrt(len(delays))
    df = len(delays) - 1
    t_critical = stats.t.ppf((1 + confidence_level) / 2, df)
    margin_of_error = t_critical * std_err

    try:
        with open("scripts/latency.txt", "w") as f:
            f.write(f"{mean}\n")
            f.write(f"{margin_of_error}\n")
        
    except Exception as e:
        print(f"Failed to write to file: {e}")
    client.close()

def main():
    if len(sys.argv) != 2:
        sys.exit(1)
    ip_address = sys.argv[1]
    samples = 500
    read_coil_from_PLC(ip_address,samples)


if __name__ == "__main__":
    time.sleep(250)
    main()