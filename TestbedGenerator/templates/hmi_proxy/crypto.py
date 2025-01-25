#!/usr/bin/env python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import time
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))
from did_iiot_dht.AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium import Dilithium2
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber 

import jwt.utils as jwt_utils

# Function to generate a timestamp
def generate_timestamp():
    return str(int(time.time())).encode('utf-8')


# Function to encrypt the secret text using AES in CBC mode
def encrypt_secret_text_with_aes_cbc(secret_text, symmetric_key):
    # Generate a random Initialization Vector (IV)
    iv = get_random_bytes(16)
    # Create an AES object in CBC mode with the symmetric key and IV
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    # Encrypt the secret text and add padding if necessary
    ciphertext = cipher.encrypt(pad(secret_text, AES.block_size))
    # Return the ciphertext and the IV
    return ciphertext, iv

# Function to decrypt the secret text using AES in CBC mode
def decrypt_secret_text_with_aes_cbc(ciphertext, iv, symmetric_key):
    # Create an AES object in CBC mode with the symmetric key and IV
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    # Decrypt the ciphertext and remove padding
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Return the decrypted text
    return decrypted_text


# Function to encrypt the message
def encrypt_message(secret_text, symmetric_key):
    # Generate the timestamp
    timestamp = generate_timestamp()
    # Encrypt the secret text with the timestamp using AES in CBC mode
    ciphertext, iv = encrypt_secret_text_with_aes_cbc(timestamp + secret_text, symmetric_key)
    # Combine the data into a single byte string
    encrypted_message = iv + ciphertext
    # Return the encrypted message
    return encrypted_message

def decrypt_message(encrypted_message, symmetric_key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    # Decrypt the ciphertext
    secret_text = decrypt_secret_text_with_aes_cbc(ciphertext, iv, symmetric_key)
    timestamp = secret_text[:10]
    secret_text = secret_text[10:]
    # Convert the timestamp to an integer
    timestamp_int = int(timestamp.decode('utf-8'))
    # Get the current timestamp
    current_timestamp = int(time.time())
    if abs(current_timestamp - timestamp_int) > 30:
        print("Invalid timestamp")
        return None, False
    else:
        return secret_text, True
    

def compute_symmetric_key(payload, kyber_private_key,auth_node_dilithium_public_key,sender_dilithium_public_key):
    # Split the payload: the first 768 bytes are 'c', the next 2420 bytes are the signature, and the rest is the certificate
    c = payload[:768]             # The first 768 bytes
    signature = payload[768:3188]     # The next 2420 bytes (768 + 2420 = 3188)
    jwt_verifiable_credential = payload[3188:] # verifiable credential
    
    jwt_verifiable_credential_json = json.loads(jwt_verifiable_credential)
    jwt_vc = jwt_verifiable_credential_json['verifiable-credential']
    jwt_array = jwt_vc.split(".")
    sender_verifiable_credential = f"{jwt_array[0]}.{jwt_array[1]}".encode('utf-8')
    jwt_signature = jwt_utils.base64url_decode(jwt_array[2].encode())
    if not Dilithium2.verify(auth_node_dilithium_public_key, sender_verifiable_credential, jwt_signature):
        print("Certificate verification failed.")
        return None, None
    if not Dilithium2.verify(sender_dilithium_public_key,c,signature):
        print("Signature verification failed.")
        return None, None
    symmetric_key = kyber.Kyber512.dec(c,kyber_private_key)
    return symmetric_key, sender_dilithium_public_key

 