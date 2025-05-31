"""
Proxy - PLC
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
import multiprocessing
import socket
import random

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
    random_number = random.randint(3,10)
    time.sleep(random_number)

print("Starting PLC's Proxy..")

did_document_delays = []
symmetric_key_delays = []
sign_sym_key_delay = []



dht_handler = DHTHandler()


keys = dict()
fragments_payload = dict()
handshake_payload = dict()
first_packet = dict()
certificates = dict()


def encrypt_aes(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def decrypt_aes(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size)

def main(loop):

    def packet_handler(packet):
        print('packet received')
        full_payload = b''
        is_verified = True
        
        pkt = IP(packet.get_payload())
        pkt.show()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Initialize the fragment payload list for the source IP if it doesn't exist
        if src_ip not in fragments_payload or fragments_payload[src_ip] == []:
            fragments_payload[src_ip] = []
            first_packet[src_ip] = pkt
        
        # Handle fragmented packets
        if pkt.flags & 1 or pkt.frag > 0:
            fragments_payload[src_ip].append(bytes(pkt[Raw].load))
            if pkt.flags == 2 or pkt.flags == 0:  # Last fragment
                full_payload = b''.join(fragments_payload[src_ip])
                pkt = first_packet[src_ip]
                pkt[TCP].remove_payload()
                pkt[TCP].add_payload(full_payload)
                # Set the DF (Don't Fragment) flag (bit 1)
                pkt.flags |= 0x2  # DF = 0x2 (0010 in binary)

                # Clear the MF (More Fragments) flag (bit 0)
                pkt.flags &= ~0x1  # MF = 0x1 (0001 in binary)
                first_packet[src_ip] = None
                fragments_payload[src_ip] = []  # Clear the payload list after reassembly
            else:
                packet.drop()
                return
        else: 
            if pkt.haslayer(Raw):
                full_payload = bytes(pkt[Raw].load)
        
        print(f"IP packet: {src_ip} -> {dst_ip}")
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print(f"TCP packet: {src_port} -> {dst_port}")
           
            # If the packet is addressed to the PLC and has a SYN
            if pkt[TCP].flags & 2 and pkt[IP].dst == device_ip:
                #Verify the Verifiable Credential signature
                jwt_verifiable_credential_json = json.loads(full_payload)
                jwt_vc = jwt_verifiable_credential_json['verifiable-credential']
                jwt_array = jwt_vc.split(".")
                m = f"{jwt_array[0]}.{jwt_array[1]}".encode('utf-8')
                signature_for_validation = jwt_utils.base64url_decode(jwt_array[2].encode())
                if dht_handler.dilith_key_manager.verify_signature(auth_node_dilithium_public_key,m,signature_for_validation,2):
                    print("Verifiable Credential verified successfully.")
                    print(type(jwt_array[1]))
                    
                    #vc_payload = json.loads(jwt_utils.base64url_decode(jwt_array[1].decode('utf-8')))
                    vc_payload = json.loads(jwt_utils.base64url_decode(jwt_array[1]))
                    did = vc_payload['sub']
                    did_suffix = dht_utils.extract_did_suffix(did)

                    start = time.time()
                    did_document_record_sender = asyncio.run_coroutine_threadsafe(
                        dht_handler.get_record_from_DHT(key=did_suffix),
                        loop
                    ).result(timeout=0.7)
                    stop = time.time()
                    retriving_did_document_delay = stop - start

                    print(f"\n\nDHT LATENCY : {retriving_did_document_delay}\n\n")

                    if did_document_record_sender:
                        print(f"DID DOCUMENT of did:iiot:{did_suffix}!")
                    else:
                        print("\nDID DOCUMENT non trovato!!\n")
                    did_document_raw_sender = did_document_record_sender[12+2420:]
                    did_document_sender = dht_utils.decode_did_document(did_document_raw_sender)
                    
                    #Retrieve sender Dilithium public key from did document
                    ver_method_dilithium_sender = did_document_sender['verificationMethod'][0]
                    sender_dilithium_jwk_pub_key = ver_method_dilithium_sender['publicKeyJwk']['x']
                    sender_dilithium_public_key = dht_utils.base64_decode_publickey(sender_dilithium_jwk_pub_key)
                    
                    # Retrieve sender Kyber public key from did document
                    ver_method_kyber_sender = did_document_sender['verificationMethod'][1]
                    sender_kyber_jwk_pub_key = ver_method_kyber_sender['publicKeyJwk']['x']
                    sender_kyber_public_key = dht_utils.base64_decode_publickey(sender_kyber_jwk_pub_key)
                    
                    certificates[src_ip] = sender_dilithium_public_key
                    is_verified = True

                    start_sym_key = time.time()
                    c, key = kyber.Kyber512.enc(sender_kyber_public_key)
                    stop_sym_key = time.time()
                    sym_key_delay = stop_sym_key - start_sym_key

                    keys[src_ip] = key

                    # Sign c
                    sign_sym_key = time.time()
                    c_sign = Dilithium2.sign(dht_handler.dilith_key_manager.get_private_key("k0"),c)
                    stop_sign_sym_key = time.time()
                    sign_sym_key = stop_sign_sym_key - sign_sym_key

                    
                    # Insert c and the Verifiable Credential into the packet payload
                    handshake_payload[src_ip] = c + c_sign + json.dumps(proxy_verifiable_credential,sort_keys=True).encode('utf-8')
                    


                    pkt[TCP].remove_payload()
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    print("Sending packet to PLC")

                    with open("retrieve_did_document.txt","w") as f:
                        f.write(f"{retriving_did_document_delay}\n")
                    
                    with open("generate_symmetric_key_encaps_kyber.txt","w") as f:
                        f.write(f"{sym_key_delay}\n")

                    with open("sign_symmetric_key_delay.txt","w") as f:
                        f.write(f"{sign_sym_key}\n")


            # If the packet is addressed to the HMI and has a SYN
            elif pkt[TCP].flags & 2 and pkt[IP].dst != device_ip:
                print("Sending packet to HMI")
                pkt[TCP].add_payload(handshake_payload[dst_ip])
                handshake_payload[dst_ip] = None
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                
                
            # If the packet is addressed to the HMI
            elif pkt[IP].dst != device_ip and pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                # OLD WAY: encrypted_data = encrypt_aes(raw_data)
                encrypted_data = crypto.encrypt_message(raw_data, keys[dst_ip])
                pkt[Raw].load = encrypted_data
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                
                # packet.set_payload(bytes(pkt))
                print("Raw data encrypted")
                
            # If the packet is addressed to the PLC
            elif pkt[IP].dst == device_ip and pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                decrypted_data, is_verified = crypto.decrypt_message(raw_data, keys[src_ip])
                if is_verified:
                    print("Valid packet")
                    pkt[Raw].load = decrypted_data
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    
                else:
                    print("Invalid packet")
                    is_verified = False
        
        packet.drop()
        
        if is_verified:
            print("Pacchetto inviato:")
            pkt.show2()
            if len(pkt) > 1400:
                # Se il pacchetto è più grande dell'MTU, frammentalo
                print(f"Pacchetto troppo grande ({len(pkt)} bytes), frammentato.")
                frags = fragment(pkt, fragsize=1400)  # 28 byte for IP and ICMP header

                
                for frag in frags:
                    send(frag)
            else:
                send(pkt)
    
    print("Starting...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, packet_handler)
    try:
        print("Running...")
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()
        os.system("iptables -D FORWARD -i eth1 -j NFQUEUE --queue-num 0")
        os.system("iptables -D FORWARD -i eth0 -j NFQUEUE --queue-num 0")
        os.system("iptables -t raw -A PREROUTING -p udp --dport 5000 -j NOTRACK")
        os.system("iptables -t raw -A OUTPUT -p udp --sport 5000 -j NOTRACK")
        os.system("iptables -A INPUT -p udp --dport 5000 -j ACCEPT")
        os.system("iptables -A INPUT -p udp --dport 5000 -j ACCEPT")
        os.system("iptables -I INPUT -i lo -j ACCEPT")
        os.system("iptables -I OUTPUT -o lo -j ACCEPT")
        os.system('iptables -X')
        



def dht_service(dht_handler:DHTHandler,proxy_ip,loop_holder):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop_holder["loop"] = loop

    loop.run_until_complete(dht_handler.start_dht_service(5000))

    dht_handler.generate_did_iiot(id_service="main-service",service_type="PLC",service_endpoint=device_ip)
    kyber_private_key = dht_handler.kyber_key_manager.get_private_key("k1")
    dilithium_private_key = dht_handler.dilith_key_manager.get_private_key("k0")
    
    if (str(proxy_ip),5000) in bootstrap_nodes:
        loop.run_until_complete(dht_handler.dht_node.bootstrap([("172.29.0.2",5000)]))
        while True:
            routing_table_kademlia = dht_handler.dht_node.protocol.router
            all_nodes = []
            for bucket in routing_table_kademlia.buckets:
                all_nodes.extend(bucket.get_nodes())

            if len(all_nodes) >= 2:
                break
            loop.run_until_complete(asyncio.sleep(2))
    else:
        loop.run_until_complete(dht_handler.dht_node.bootstrap(bootstrap_nodes))
        #loop.run_until_complete(asyncio.sleep(random_number+2))

    loop.run_until_complete(dht_handler.insert_did_document_in_the_DHT())

    loop.run_until_complete(asyncio.sleep(10))
    loop.run_until_complete(dht_handler.get_vc_from_authoritative_node())
    print("[PLC's Proxy] - Verifiable Credential obtained from Issuer Node") 

    start_t = time.time()
    authoritative_node_did_doc_record = loop.run_until_complete(dht_handler.get_record_from_DHT(key="vc-issuer"))
    stop_t = time.time()
    print(f"Retrieve time for IssuerNode's DID Document: {stop_t - start_t}")
    authoritative_node_did_doc_raw = authoritative_node_did_doc_record[12+2420:]
    auth_node_did_document = dht_utils.decode_did_document(authoritative_node_did_doc_raw)
    var_method = auth_node_did_document['verificationMethod'][0]
    auth_node_jwk_pub_key = var_method['publicKeyJwk']['x']
    auth_node_dilithium_public_key = dht_utils.base64_decode_publickey(auth_node_jwk_pub_key)

    with open("auth_node_pub_key","wb") as f:
        f.write(auth_node_dilithium_public_key)

    loop.run_until_complete(dht_handler.dht_node._refresh_table())

    dht_ready.set()
    
    loop.run_forever()



if __name__ == "__main__":

    loop_holder = {}

    dht_ready = threading.Event()
    dht_service_thread = threading.Thread(target=dht_service,args=(dht_handler,proxy_ip,loop_holder,),daemon=True)
    dht_service_thread.start()

    dht_ready.wait()

    kyber_private_key = dht_handler.kyber_key_manager.get_private_key("k1")
    dilithium_private_key = dht_handler.dilith_key_manager.get_private_key("k0")

    with open("vc.json", "r") as f:
        proxy_verifiable_credential = json.loads(f.read())

    with open("auth_node_pub_key","rb") as f:
        auth_node_dilithium_public_key = f.read()
    
    routing_table_kademlia = dht_handler.dht_node.protocol.router
    nodes = []
    for bucket in routing_table_kademlia.buckets:
        nodes.extend(bucket.get_nodes())
        
    print(f"\nBuckets: {nodes}")
    loop = loop_holder['loop']
    main()
    



