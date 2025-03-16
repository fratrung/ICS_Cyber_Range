# ICS_Cyber_Range

## Overview

**ICS_Cyber_Range** is a cyber range designed to simulate and test a secure network infrastructure using public key cryptography. The goal is to secure Modbus communication, a widely used protocol in industrial control systems (ICS). This project uses OpenPLC to simulate a Programmable Logic Controller (PLC) and provides a controlled environment to experiment with securing ICS protocols.

### What is a Cyber Range?

A cyber range is a virtual environment that allows researchers, developers, and security professionals to safely simulate, test, and train in cybersecurity. It provides a realistic, isolated setup for experimenting with network configurations, attack simulations, and security defenses without impacting real-world systems.

### Network Components

- **Issuer Node**: Generates Verifiable Credential in JWT format and distributes them across the network.
- **HMI (Human-Machine Interface)**: The interface for monitoring and controlling the PLC.
- **PLC (Programmable Logic Controller)**: Simulated using OpenPLC to control industrial processes.
- **Proxies**: Each device in the network (HMI and PLC) has its own proxy to manage secure communication. The proxies are peers of the 
   DHT network. Each Proxies are identified by a did:iiot.
- **Attacker**: A simulated attacker to test the security of the system.
- **DHT**: Used per storing DID Document of the proxies.

## Getting Started

Follow the steps below to set up and run the ICS_Cyber_Range.

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone -recurse-submodules https://github.com/fratrung/ICS_Cyber_Range.git
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
- [did:iiot Method] (https://github.com/fratrung/did-iiot)