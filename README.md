# ICS_Cyber_Range

## Overview

**ICS_Cyber_Range** is a cyber range designed to simulate and test a secure, decentralized infrastructure that utilizes post-quantum cryptography for robust security. It leverages did:iiot for decentralized authentication and key exchange, based on a self-sovereign identity model. The goal is to secure Modbus communication, a widely used protocol in industrial control systems (ICS). This project uses OpenPLC to simulate a Programmable Logic Controller (PLC) and provides a controlled environment to experiment with securing ICS protocols.

### What is a Cyber Range?

A cyber range is a virtual environment that allows researchers, developers, and security professionals to safely simulate, test, and train in cybersecurity. It provides a realistic, isolated setup for experimenting with network configurations, attack simulations, and security defenses without impacting real-world systems.

### Network Components


- **HMI (Human-Machine Interface)**: The interface for monitoring and controlling the PLC.
- **PLC (Programmable Logic Controller)**: Simulated using OpenPLC to control industrial processes.
- **Proxies**: Each device in the network (HMI and PLC) is assigned its own proxy to handle secure communication. The proxies identification within the industrial network is managed through did:iiot. However, they operate as peers within the DHT network.
- **DHT**: A modified DHT used to store records consisting of a DID Document and its corresponding digital signature. The digital signature can be verified using the public key contained within the DID Document itself, ensuring both the authenticity and integrity of the stored data. This approach allows the DHT to function as a Verifiable Data Registry.
- **Issuer Node**: This node is responsible for generating Verifiable Credentials in JWT format and distributing them across the network. It is only activated when a new device needs to be added to the industrial network. The Issuer Node responds to issuance requests manually triggered by an operator, and once the operation is completed, it is deactivated. Communication between nodes within the network, including secure communication, key exchange, and key rotation, is autonomously and decentralized, handled by the proxies.
- **Attacker**: A simulated attacker to test the security of the system.


## Getting Started

Follow the steps below to set up and run the ICS_Cyber_Range.

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone --recurse-submodules https://github.com/fratrung/ICS_Cyber_Range.git
cd ICS_Cyber_Range/TestbedGenerator
```

### 2. Build and Start the Environment

Use **testbed_generator.py** to build and start the entire environment:
```bash
sudo python3 testbed_generator.py
```

### 5. Test communication with HMI
Access the bash of the HMI container:

```bash
docker exec -it hmi bash
```

Start the testing script:
```bash
cd scripts
python3 client.py
```

## Acknowledgements
- [OpenPLC] (https://github.com/thiagoralves/OpenPLC_v3)
- [Dilithium-py] (https://github.com/GiacomoPope/dilithium-py)
- [Kyber-py] (https://github.com/GiacomoPope/kyber-py)
- [did:iiot] (https://github.com/fratrung/did-iiot)
- [did-iiot-dht] (https://github.com/fratrung/did-iiot-dht)