
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'dilithium'))
from did_iiot_dht.AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2
import time
import json

from did_iiot_dht.authoritative_node import AuthoritativeNode
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import asyncio

 
auth_node_service = FastAPI()
auth_node = AuthoritativeNode()

class VCRequest(BaseModel):
    did_sub: str
    modbus_operations: Optional[List[str]] = []

@auth_node_service.get("/get-vc")
async def generate_vc(did_sub: str, modbus_operations: Optional[List[str]] = Query(default=[])):
    #loop = asyncio.new_event_loop()
    #asyncio.set_event_loop(loop)
    if not did_sub:
        raise HTTPException(status_code=400, detail="Missing 'did_sub' parameter")

    try:
        result = auth_node.generate_vc(did_sub, modbus_operations)
        if result is None:
            raise HTTPException(status_code=404, detail="No result found")
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
                            
                            
        
async def configure_auth_node(auth_node: AuthoritativeNode):
    auth_node.generate_authoritative_node_did_iiot("172.29.0.2:5007")
    await auth_node.start_dht_service(5000)
    await auth_node.dht_node.bootstrap([("172.29.0.8",5000),("172.29.0.101",8001)])
    await auth_node.insert_did_document_in_the_DHT()
    await auth_node.dht_node.stop()
    
if __name__ == "__main__":
    uvicorn.run(auth_node_service, host="0.0.0.0", port=5007)
    time.sleep(20)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(configure_auth_node(auth_node))
    #Avvio FastAPI server
    
    


#app = Flask(__name__)

# Generate a Dilithium key pair 
#dilithium_public_key,dilithium_private_key = Dilithium2.keygen()

# Save public key to file 
#with open('dilithium_public_key', 'wb') as f:
#    f.write(dilithium_public_key)

# Save private key to file
#with open('dilithium_private_key', 'wb') as f:
#    f.write(dilithium_private_key)
    

#@app.route('/generate_certificate', methods=['POST'])
#def generate_certificate():
#    data = request.json
#    kyber_public_key = data['kyber_public_key']
#    dilithium_public_key_client = data['dilithium_public_key']
#    organization = "UniMe"
#    ip_address = request.remote_addr
    
    # Create the certificate JSON
#    certificate = {
#        "organization": organization,
#        "ip_address": ip_address,
#        "kyber_public_key": kyber_public_key,
#        "dilithium_public_key": dilithium_public_key_client,
#        "issuer_dilithium_public_key": dilithium_public_key.hex(),
#        "not_valid_before": time.time(),
#        "not_valid_after": time.time() + 31536000 # 1 year
#    }
    
    # Serialize the certificate to JSON
#    certificate_json = json.dumps(certificate, sort_keys=True).encode('utf-8')
    
    # Sign the certificate with the Dilithium private key
#    signature = Dilithium2.sign(dilithium_private_key, certificate_json)
    
    # Add the signature to the certificate
#    certificate["signature"] = signature.hex()
    
#    return jsonify(certificate)

#if __name__ == '__main__':
#    app.run(debug=False, host='0.0.0.0', port=5000)
