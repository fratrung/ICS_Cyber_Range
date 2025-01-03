import requests
import json
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))
from dilithium import Dilithium2
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber 

# Generate a Dilithium key pair (this is a placeholder, replace with actual key generation)
kyber_public_key, kyber_private_key = kyber.Kyber512.keygen()

#writes the private key to a file
with open('kyber_private_key.txt', 'wb') as f:
    f.write(kyber_private_key)

dilithium_public_key, dilithium_private_key = Dilithium2.keygen()

#writes the private key to a file
with open('dilithium_private_key.txt', 'wb') as f:
    f.write(dilithium_private_key)

# Data for the certificate
data = {
    "kyber_public_key": kyber_public_key.hex(),
    "dilithium_public_key": dilithium_public_key.hex(),
}

# Request the certificate from the server
response = requests.post("http://172.28.0.10:5000/generate_certificate", json=data)
certificate = response.json()

# Extract the signature and remove it from the certificate
signature = bytes.fromhex(certificate.pop("signature"))

# Serialize the certificate JSON without the signature for verification
certificate_json = json.dumps(certificate, sort_keys=True).encode('utf-8')

# Verify the signature using the issuer's Dilithium public key
issuer_dilithium_public_key = certificate["issuer_dilithium_public_key"]

if Dilithium2.verify(bytes.fromhex(issuer_dilithium_public_key), certificate_json, signature):
    print("Certificate verified successfully.")
    # we should also verify the expiry date of the certificate
    # reinsert the signature into the certificate
    certificate["signature"] = signature.hex()
    # Save the certificate to a file
    with open('certificate', 'w') as f:
        f.write(json.dumps(certificate, sort_keys=True))
else: 
    print("Certificate verification failed.")
