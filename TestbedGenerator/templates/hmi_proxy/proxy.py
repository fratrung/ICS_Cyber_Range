from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'python-netfilterqueue/netfilterqueue'))
from netfilterqueue import NetfilterQueue
import crypto
import json
import threading
#sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))

from did_iiot_dht.AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium import Dilithium2
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber 

sys.path.append(os.path.join(os.path.dirname(__file__), 'did_iiot_dht'))
from did_iiot_dht.dht_handler import DHTHandler
import did_iiot_dht.utils as dht_utils
import jwt.utils as jwt_utils
import asyncio
import time
import multiprocessing
import socket
from network_discover import send_broadcast_message


def get_container_ip():
    ip = os.popen("hostname -I | awk '{print $1}'").read().strip()
    return ip
  
print("Starting HMI's Proxy..")

iptablesr1 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"


os.system(iptablesr1)
os.system(iptablesr2)


device_ip = os.getenv('DEVICE_IP')
proxy_ip = get_container_ip()
time.sleep(5)
peers = send_broadcast_message()



dht_handler = DHTHandler()


keys = {}
fragments_payload = {}  
first_packet = {}
certificates = {}
sequences = []
synlist = []
retr_counter = 0
tot_counter = 0

def main():

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def packet_handler(packet):
        print('\n\nPacket received:')
        
        full_payload = b''
        is_verified = True
        
        pkt = IP(packet.get_payload())
        pkt.show()
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                print("SSH packet")
                packet.accept()
                return
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
            global retr_counter
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print(f"TCP packet: {src_port} -> {dst_port}")
            seq = pkt[TCP].seq
            if seq in sequences and not pkt[TCP].flags & 2:
                print("Retransmitted packet")
            else: 
                sequences.append(seq)

            # If the packet is addressed to the HMI and has a SYN
            if pkt[TCP].flags & 2 and pkt[IP].dst == device_ip:
                #DA CHIEDERE A MANUEL se questo è corretto
                verfiable_credential = full_payload[3188:]
                jwt_verifiable_credential_json = json.loads(verfiable_credential)
                jwt_vc = jwt_verifiable_credential_json['verifiable-credential']
                jwt_array = jwt_vc.split(".")
                vc_sender_payload = json.loads(jwt_utils.base64url_decode(jwt_array[1]))
                did = vc_sender_payload['sub']
                did_suffix = dht_utils.extract_did_suffix(did)
                did_document_record_sender = loop.run_until_complete(dht_handler.get_record_from_DHT(key=did_suffix))
                did_document_raw_sender = did_document_record_sender[12+2420:]
                did_document_sender = dht_utils.decode_did_document(did_document_raw_sender)
            
                #Retrieve sender Dilithium public key from did document
                ver_method_dilithium_sender = did_document_sender['verificationMethod'][0]
                sender_dilithium_jwk_pub_key = ver_method_dilithium_sender['publicKeyJwk']['x']
                sender_dilithium_public_key = dht_utils.base64_decode_publickey(sender_dilithium_jwk_pub_key) 

                keys[src_ip], sign_key = crypto.compute_symmetric_key(full_payload, kyber_private_key,auth_node_dilithium_public_key,sender_dilithium_public_key)
                if keys[src_ip] is None:
                    print("Error computing symmetric key")
                    is_verified = False
                else:
                    certificates[src_ip] = sign_key
                if is_verified:
                    print("Symmetric key saved: ", keys[src_ip])
                    pkt[TCP].remove_payload()
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                else:
                    print("Signature not verified")
                   
            # If the packet has the SYN flag and is addressed to the PLC
            elif pkt[TCP].flags & 2 and pkt[IP].dst != device_ip:
                # Send the certificate to the PLC
                print("SYN packet received, starting handshake\n")
                if pkt[IP].dst in synlist:
                    print("SYN packet already sent, not resending")
                    is_verified = False
                else:
                    synlist.append(pkt[IP].dst)
                if is_verified:
                    certificate_json = json.dumps(proxy_verifiable_credential, sort_keys=True).encode('utf-8')
                    pkt[TCP].add_payload(certificate_json)
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                
            # If the packet is addressed to the PLC
            elif pkt[IP].dst != device_ip and pkt.haslayer(Raw):
                if pkt[IP].dst in synlist:
                    synlist.remove(pkt[IP].dst)
                raw_data = bytes(pkt[Raw].load)
                print("Encrypting packet with ", keys[dst_ip])
                encrypted_data = crypto.encrypt_message(raw_data, keys[dst_ip])
                pkt[Raw].load = encrypted_data
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                print("Modbus packet encrypted")
                
            # If the packet is addressed to the HMI
            elif pkt[IP].dst == device_ip and pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                print("Decrypting packet with ", keys[src_ip])
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
            print("\nSending the following packet: ")
            pkt.show2()
            if len(pkt) > 1400:
                # Se il pacchetto è più grande dell'MTU, frammentalo
                print(f"Pacchetto troppo grande ({len(pkt)} bytes), frammentato.")
                frags = fragment(pkt, fragsize=1400)  # 28 byte per l'header IP e ICMP

                # Invia ogni frammento separatamente
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
        os.system('iptables -X')




def broadcast_listener(port=7000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", port))
    #server_socket.listen(5)

    print(f"[*] Listener attivo sulla porta {port}...")

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            print(f"[*] Ricevuto messaggio da {addr}: {data.decode()}")
            
            response = f"{proxy_ip}:5000" 
            server_socket.sendto(response.encode(), addr)
            
        except Exception as e:
           print(f"Errore nel listener: {e}")




if __name__ == "__main__":

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(dht_handler.start_dht_service(5000))
    
    broadcast_listener_thread = threading.Thread(target=broadcast_listener,daemon=True)
    broadcast_listener_thread.start()
    
    dht_handler.generate_did_iiot(id_service="main-service",service_type="HMI",service_endpoint=device_ip)
    kyber_private_key = dht_handler.kyber_key_manager.get_private_key("k1")
    dilithium_private_key = dht_handler.dilith_key_manager.get_private_key("k0") 
    
    if peers:
        loop.run_until_complete(dht_handler.dht_node.bootstrap(peers))
        loop.run_until_complete(asyncio.sleep(3))
        loop.run_until_complete(dht_handler.insert_did_document_in_the_DHT())
    else:
        print("No peers in the network!")
        time.sleep(5)
        routing_table_kademlia = dht_handler.dht_node.protocol.router
        all_nodes = []
        while True:
            for bucket in routing_table_kademlia.buckets:
                all_nodes.extend(bucket.get_nodes())
            if len(all_nodes) >= 2:
                break
            print(f"Node bucket: {all_nodes} nodes")
            loop.run_until_complete(asyncio.sleep(3))
        
        
        loop.run_until_complete(dht_handler.insert_did_document_in_the_DHT())
        print(f"Node bucket: {all_nodes} nodes , after setting DID Document in the DHT")
    
    
    
    loop.run_until_complete(asyncio.sleep(10))
    loop.run_until_complete(dht_handler.get_vc_from_authoritative_node())
    print("[HMI's Proxy] - Verifiable credential obtained from Authoritative Node")

    with open("vc.json", "r") as f:
        proxy_verifiable_credential = json.loads(f.read())
    
    
    
    authoritative_node_did_doc_record = loop.run_until_complete(dht_handler.get_record_from_DHT(key="vc-issuer"))
    authoritative_node_did_doc_raw = authoritative_node_did_doc_record[12+2420:]
    auth_node_did_document = dht_utils.decode_did_document(authoritative_node_did_doc_raw)
    var_method = auth_node_did_document['verificationMethod'][0]
    auth_node_jwk_pub_key = var_method['publicKeyJwk']['x']
    auth_node_dilithium_public_key = dht_utils.base64_decode_publickey(auth_node_jwk_pub_key)

    netfilter_thread = threading.Thread(target=main,daemon=True)
    netfilter_thread.start()
    
    loop.run_forever()
