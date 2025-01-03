from flask import Flask, request, jsonify
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))
from dilithium import Dilithium2
import time
import json

app = Flask(__name__)

# Generate a Dilithium key pair 
dilithium_public_key,dilithium_private_key = Dilithium2.keygen()

# Save public key to file 
with open('dilithium_public_key', 'wb') as f:
    f.write(dilithium_public_key)

# Save private key to file
with open('dilithium_private_key', 'wb') as f:
    f.write(dilithium_private_key)
    

@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    kyber_public_key = data['kyber_public_key']
    dilithium_public_key_client = data['dilithium_public_key']
    organization = "UniMe"
    ip_address = request.remote_addr
    
    # Create the certificate JSON
    certificate = {
        "organization": organization,
        "ip_address": ip_address,
        "kyber_public_key": kyber_public_key,
        "dilithium_public_key": dilithium_public_key_client,
        "issuer_dilithium_public_key": dilithium_public_key.hex(),
        "not_valid_before": time.time(),
        "not_valid_after": time.time() + 31536000 # 1 year
    }
    
    # Serialize the certificate to JSON
    certificate_json = json.dumps(certificate, sort_keys=True).encode('utf-8')
    
    # Sign the certificate with the Dilithium private key
    signature = Dilithium2.sign(dilithium_private_key, certificate_json)
    
    # Add the signature to the certificate
    certificate["signature"] = signature.hex()
    
    return jsonify(certificate)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
