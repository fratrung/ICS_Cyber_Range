"""
Proxy - HMI
"""
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'python-netfilterqueue/netfilterqueue'))
from netfilterqueue import NetfilterQueue
import crypto
import json
import sys
import threading
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber 

sys.path.append(os.path.join(os.path.dirname(__file__), 'did_iiot_dht'))
from did_iiot_dht.AuthKademlia.modules import Dilithium2
from did_iiot_dht.dht_handler import DHTHandler
import did_iiot_dht.utils as dht_utils 
import jwt.utils as jwt_utils
import asyncio
import time
import base64
import random
import hashlib
import fcntl




def get_container_ip():
    ip = os.popen("hostname -I | awk '{print $1}'").read().strip()
    return ip

def print_iptables_rules():
    try:
        stream = os.popen('iptables -L')
        output = stream.read()
        print(f"iptables rules:\n {output}")
        stream.close()
    except Exception as e:
        print(f"error: {e}")




iptablesr1 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"




os.system(iptablesr1)
os.system(iptablesr2)
os.system("iptables -t raw -A PREROUTING -p udp --dport 5000 -j NOTRACK")
os.system("iptables -t raw -A OUTPUT -p udp --sport 5000 -j NOTRACK")
os.system("iptables -A INPUT -p udp --dport 5000 -j ACCEPT")
os.system("iptables -A INPUT -p udp --dport 5000 -j ACCEPT")
os.system("iptables -I INPUT -i lo -j ACCEPT")
os.system("iptables -I OUTPUT -o lo -j ACCEPT")

print_iptables_rules()

device_ip = os.getenv('DEVICE_IP')
proxy_ip = get_container_ip()


bootstrap_nodes = [("172.29.0.181",5000),("172.29.0.63",5000),("172.29.0.2",5000)] #entry nodes for DHT 

if (str(proxy_ip),5000) not in bootstrap_nodes:
    random_number = random.randint(9,17)
    time.sleep(random_number)
else:
    time.sleep(1)
 

print("Starting HMI's Proxy..")

dht_handler = DHTHandler()
key_rotation_test_results = []


async def test_key_rotation():
    await dht_handler.start_dht_service(5000)
    dht_handler.generate_did_iiot(id_service="main-service",service_type="Node",service_endpoint=device_ip)
    if (str(proxy_ip),5000) in bootstrap_nodes:
        await dht_handler.dht_node.bootstrap([("172.29.0.2",5000)])
        while True:
            routing_table_kademlia = dht_handler.dht_node.protocol.router
            all_nodes = []
            for bucket in routing_table_kademlia.buckets:
                all_nodes.extend(bucket.get_nodes())

            if len(all_nodes) >= 2:
                break
            await asyncio.sleep(0.5) 
            
    else:
        await dht_handler.dht_node.bootstrap(bootstrap_nodes)

    await dht_handler.insert_did_document_in_the_DHT()
    await asyncio.sleep(100)

    if (str(proxy_ip),5000) not in bootstrap_nodes:
        random_number = random.randint(7,13)
        await asyncio.sleep(random_number)

    await dht_handler.get_vc_from_authoritative_node()
    print("[HMI's Proxy] - Verifiable Credential obtained from Issuer Node") 

    #with open("vc.json", "r") as f:
    #    proxy_verifiable_credential = json.loads(f.read())

    #with open("issuer_node_public_key.txt","rb") as f:
    #    auth_node_dilithium_public_key = f.read()

    await dht_handler.dht_node._refresh_table()

    routing_table_kademlia = dht_handler.dht_node.protocol.router
    nodes = []
    for bucket in routing_table_kademlia.buckets:
        nodes.extend(bucket.get_nodes())
        
    print(f"\nBuckets:{nodes}")

    #await asyncio.sleep(60)
    shared_status_path = "/shared_status/status.txt"
    try:
        with open(shared_status_path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            value = int(f.read().strip() or 0)
            f.seek(0)
            f.write(str(value + 1))
            f.truncate()
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        print(f"[ERROR] Failed to update shared status: {e}")
        return
    
    while True:
        try:
            with open(shared_status_path, "r") as f:
                current_status = int(f.read().strip() or 0)
                if current_status >= 20:
                    break
        except:
            pass
        await asyncio.sleep(0.8)

    #print("Starting Key Rotation Measurement")
    print("Starting Key Rotation Measurement at", int(time.time()))
    for _ in range(100):
        start_t = time.perf_counter()
        result = await dht_handler.key_rotation()

        elapsed = time.perf_counter() - start_t
        record = {"delay":elapsed, "result": result}
        key_rotation_test_results.append(record)
        print(f"key rotation latency: {elapsed} sec")

        await asyncio.sleep(1)
        
    with open("key_rotation_latency", "w") as f:
           f.write(f"{key_rotation_test_results}")

    success = 0
    for elem in key_rotation_test_results:
        if elem['result'] == True:
            success +=1
    print(f"{success}/100 Key rotation has been completed")
    print(f"{key_rotation_test_results}")
    
    while True:
        await asyncio.sleep(2)


if __name__ == "__main__":
 
    asyncio.run(test_key_rotation())



