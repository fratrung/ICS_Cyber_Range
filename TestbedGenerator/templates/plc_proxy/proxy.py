"""
Proxy 1 - PLC
"""
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from netfilterqueue import NetfilterQueue
import crypto
import json
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))
from did_iiot_dht.AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2
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
from network_discover import load_peers

iptablesr1 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"
os.system(iptablesr1)
os.system(iptablesr2)

device_ip = os.getenv('DEVICE_IP')
peers = load_peers()

dht_handler = DHTHandler()

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

loop.run_until_complete(dht_handler.start_dht_service(5000))
loop.run_until_complete(dht_handler.dht_node.bootstrap(peers)) 

dht_handler.generate_did_iiot(id_service="main-service",service_type="PLC",service_endpoint=device_ip)
loop.run_until_complete(dht_handler.insert_did_document_in_the_DHT())
time.sleep(50)
loop.run_until_complete(dht_handler.get_vc_from_authoritative_node())
print("VC ottenuto per il proxy del PLC")


#fine parte aggiunta 

keys = dict()
fragments_payload = dict()
handshake_payload = dict()
first_packet = dict()
certificates = dict()


kyber_private_key = dht_handler.kyber_key_manager.get_private_key("k0")
dilithium_private_key = dht_handler.dilith_key_manager.get_private_key("k0")

with open("vc.json","r") as f:
    proxy_verifiable_credential = json.load(f.read())

#with open("kyber_private_key.txt", "rb") as f:
#    kyber_private_key = f.read()

#with open("dilithium_private_key.txt", "rb") as f:
#    dilithium_private_key = f.read()
    
#with open("certificate", "r") as f:
#    proxy_certificate = json.loads(f.read())



#issuer_dilithium_public_key = proxy_certificate["issuer_dilithium_public_key"]

authoritative_node_did_doc_record = loop.run_until_complete(dht_handler.get_record_from_DHT(key="did:iiot:vc-issuer"))
authoritative_node_did_doc_raw = authoritative_node_did_doc_record[12+2420:]
auth_node_did_document = dht_utils.decode_did_document(authoritative_node_did_doc_raw)
var_method = auth_node_did_document['verificationMethod'][0]
auth_node_jwk_pub_key = var_method['publicKeyJwk']['x']
auth_node_dilithium_public_key = dht_utils.base64_decode_publickey(auth_node_jwk_pub_key)

def encrypt_aes(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def decrypt_aes(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size)

def main():
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
                # Verify the certificate signature
                #certificate_json = json.loads(full_payload)
                #signature = bytes.fromhex(certificate_json.pop("signature"))
                #certificate = json.dumps(certificate_json, sort_keys=True).encode('utf-8')
                #if Dilithium2.verify(bytes.fromhex(issuer_dilithium_public_key), certificate, signature):
                #    print("Certificate verified successfully.")
                #    certificates[src_ip] = certificate_json["dilithium_public_key"]
                #    is_verified = True
                #    other_proxy_kyber_public_key = bytes.fromhex(certificate_json["kyber_public_key"])
                #    c, key = kyber.Kyber512.enc(other_proxy_kyber_public_key)  # c length = 768
                #    keys[src_ip] = key
                    # Sign c
                #    c_sign = Dilithium2.sign(dilithium_private_key, c)  # sign length = 2420
                    # Insert c and the certificate into the packet payload
                    #handshake_payload[src_ip] = c + c_sign + json.dumps(proxy_certificate, sort_keys=True).encode('utf-8')

                #Verify the Verifiable Credential signature
                jwt_verifiable_credential_json = json.load(full_payload)
                jwt_array = jwt_verifiable_credential_json.split(".")
                m = f"{jwt_array[0]}.{jwt_array[1]}".encode('utf-8')
                signature_for_validation = jwt_utils.base64url_decode(jwt_array[2].encode())
                if dht_handler.dilith_key_manager.verify_signature(auth_node_dilithium_public_key,m,signature_for_validation,2):
                    print("Certificate verified successfully.")
                    
                    vc_payload = json.loads(jwt_utils.base64url_decode(jwt_array[1].decode('urf-8')))
                    did = vc_payload['sub']
                    did_suffix = dht_utils.extract_did_suffix(did)
                    
                    did_document_record_sender = loop.run_until_complete(dht_handler.get_record_from_DHT(key=did_suffix))
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
                    c, key = kyber.Kyber512.enc(sender_kyber_public_key)
                    keys[src_ip] = key
                    # Sign c
                    c_sign = Dilithium2.sign(dht_handler.dilith_key_manager.get_private_key("k0"),c)
                    # Insert c and the Verifiable Credential into the packet payload
                    handshake_payload[src_ip] = c + c_sign + json.dumps(proxy_verifiable_credential,sort_keys=True).encode('utf-8')
                    


                    pkt[TCP].remove_payload()
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    print("Sending packet to PLC")
                    
                        
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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", port))
    server_socket.listen(5)

    print(f"[*] Listen for broadcast message on port {port}...")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            #print(f"[*] Connessione ricevuta da {client_address}")

            response = f"{device_ip}:5000"
            client_socket.sendall(response.encode())

            client_socket.close()
        except Exception as e:
            print(f"Error: {e}")


def multiprocess_main():
    process1 = multiprocessing.Process(target=main)
    process2 = multiprocessing.Process(target=broadcast_listener,args=(7000,))
    process1.start()
    process2.start()
    process1.join()
    process2.join()
    
    
if __name__ == "__main__":
    main()
