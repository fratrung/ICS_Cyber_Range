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
from dilithium import Dilithium2
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber 

iptablesr1 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"
os.system(iptablesr1)
os.system(iptablesr2)

keys = dict()
fragments_payload = dict()
handshake_payload = dict()
first_packet = dict()
certificates = dict()

with open("kyber_private_key.txt", "rb") as f:
    kyber_private_key = f.read()

with open("dilithium_private_key.txt", "rb") as f:
    dilithium_private_key = f.read()
    
with open("certificate", "r") as f:
    proxy_certificate = json.loads(f.read())
    
issuer_dilithium_public_key = proxy_certificate["issuer_dilithium_public_key"]

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
            if pkt[TCP].flags & 2 and pkt[IP].dst == "172.29.0.5":
                # Verify the certificate signature
                certificate_json = json.loads(full_payload)
                signature = bytes.fromhex(certificate_json.pop("signature"))
                certificate = json.dumps(certificate_json, sort_keys=True).encode('utf-8')
                if Dilithium2.verify(bytes.fromhex(issuer_dilithium_public_key), certificate, signature):
                    print("Certificate verified successfully.")
                    certificates[src_ip] = certificate_json["dilithium_public_key"]
                    is_verified = True
                    other_proxy_kyber_public_key = bytes.fromhex(certificate_json["kyber_public_key"])
                    c, key = kyber.Kyber512.enc(other_proxy_kyber_public_key)  # c length = 768
                    keys[src_ip] = key
                    # Sign c
                    c_sign = Dilithium2.sign(dilithium_private_key, c)  # sign length = 2420
                    # Insert c and the certificate into the packet payload
                    handshake_payload[src_ip] = c + c_sign + json.dumps(proxy_certificate, sort_keys=True).encode('utf-8')
                    pkt[TCP].remove_payload()
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    print("Sending packet to PLC")
                    pkt.show2()
                        
            # If the packet is addressed to the HMI and has a SYN
            elif pkt[TCP].flags & 2 and pkt[IP].dst != "172.29.0.5":
                print("Sending packet to HMI")
                pkt[TCP].add_payload(handshake_payload[dst_ip])
                handshake_payload[dst_ip] = None
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                pkt.show2()
                
            # If the packet is addressed to the HMI
            elif pkt[IP].dst != "172.29.0.5" and pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                # OLD WAY: encrypted_data = encrypt_aes(raw_data)
                encrypted_data = crypto.encrypt_message(raw_data, keys[dst_ip])
                pkt[Raw].load = encrypted_data
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                pkt.show2()
                # packet.set_payload(bytes(pkt))
                print("Raw data encrypted")
                
            # If the packet is addressed to the PLC
            elif pkt[IP].dst == "172.29.0.5" and pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                decrypted_data, is_verified = crypto.decrypt_message(raw_data, keys[src_ip])
                if is_verified:
                    print("Valid packet")
                    pkt[Raw].load = decrypted_data
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    pkt.show2()
                else:
                    print("Invalid packet")
                    is_verified = False
        
        packet.drop()
        if is_verified:
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
        

if __name__ == "__main__":
    main()
