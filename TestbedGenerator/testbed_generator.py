import os
import yaml
import requests
import time

def create_volume_directories(num_hmi, num_plc):
    hmi_proxy_template = "templates/hmi_proxy"
    plc_proxy_template = "templates/plc_proxy"
    hmi_template = "hmi"

    #flush volumes direcory
    if os.path.exists('volumes'):
        os.system('rm -r volumes')
    
    os.makedirs('volumes')

    for i in range(1, num_hmi + 1):
        os.system(f'cp -rf {hmi_proxy_template} volumes/hmi_proxy{i}')
    for i in range(1, num_plc + 1):
        os.system(f'cp -rf {plc_proxy_template} volumes/plc_proxy{i}')
    for i in range(1,num_hmi + 1):
        os.system(f'cp -rf {hmi_template} volumes/hmi{i}')

    #used for sync key_rotation experiment
    shared_dir = 'volumes/hmi_proxy_shared'
    os.makedirs(shared_dir, exist_ok=True)
    with open(os.path.join(shared_dir, 'status.txt'), 'w') as f:
        f.write('0')

def generate_compose(num_hmi, num_plc,cpus,cm4_ram):
    netem_prelude_proxy = (
        'tc qdisc add dev eth0 root netem '
        'delay 25ms 0.5ms distribution normal '
        'rate 100mbit '
    )
    netem_prelude_device = (
        'tc qdisc add dev eth0 root netem '
        'delay 5ms 0.2ms distribution normal '
        'rate 100mbit '
    )
    compose = {
        'version': '3.9',
        'services': {
            'issuer_node': {
                'build': './issuer_node',
                'ports': ['5007:5007'],
                'networks': {
                    'network1': {
                        'ipv4_address': '172.29.0.2'
                    }
                },
                'cap_add': ['NET_ADMIN'],
                'command': ['sh', '-c', f'{netem_prelude_proxy} && exec python did_iiot_dht/issuer_node.py']
            }
        },
        'networks': {
            'network1': {
                'driver': 'bridge',
                'name': 'network1',
                'ipam': {
                    'config': [
                        {'subnet': '172.29.0.0/24'}
                    ]
                }
            }
        },
    }

    # Add PLC services and proxies
    for i in range(1, num_plc + 1):
        plc_name = f'plc{i}'
        proxy_name = f'plc_proxy{i}'

        plc_ip = f'172.29.0.{i + 121}'
        proxy_ip = f'172.29.0.{i + 180}'
        ports = [f"800{i}:8080"]
        if i >9:
            ports =  [f"80{i}:8080"]
        compose['services'][plc_name] = {
            'container_name': plc_name,
            'build': f'./plc/plc1',
            'ports': ports,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': plc_ip}
            },
            'command': [ 'sh', '-c',f'{netem_prelude_device}']
        }

        compose['services'][proxy_name] = {
            'container_name': proxy_name,
            'build': './proxy',
            'volumes': [f'./volumes/plc_proxy{i}:/scripts'],
            'tty': True,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': proxy_ip}
            },
            'environment': {
                'DEVICE_IP': plc_ip
            },
            'command': (
                #f"sh -c \"apt-get update && " +
                #f"apt-get install -y iproute2 && "
                f"sh -c \"{netem_prelude_proxy} && "  +
                f"apt-get update && apt-get install -y iproute2 && "
                + ''.join([
                    f"ip route add 172.29.0.{j + 121} via 172.29.0.{j + 180} && "
                    for j in range(1, num_plc + 1)  if j != i
                ])
                + ''.join([
                    f"ip route add 172.29.0.{k + 2} via 172.29.0.{k + 62} && "
                    for k in range(1, num_hmi + 1) 
                ]) +
                f"cd scripts && " +
                f"pip install ./python-netfilterqueue &&" +
                f"pip install PyJWT &&" +
                f"pip install u-msgpack-python && " +
                f"pip install cryptography httpx && " +
                f"chmod +x start_proxy.sh &&" +
                f"exec ./start_proxy.sh\""
            )
        }

    # Add HMI services and proxies
    for i in range(1, num_hmi + 1):
        hmi_name = f'hmi{i}'
        proxy_name = f'hmi_proxy{i}'

        hmi_ip = f'172.29.0.{i + 2}'
        proxy_ip = f'172.29.0.{i + 62}'

        # Determine corresponding PLC proxy
        plc_proxy_ip = f'172.29.0.{i + 180}' if i <= num_plc else ""
        plc_ip = f'172.29.0.{i + 121}' if i <= num_plc else ""

        compose['services'][hmi_name] = {
            'container_name': hmi_name,
            'build': './hmi',
            'volumes': [f'./volumes/hmi{i}/scripts:/scripts'],
            'tty': True,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': hmi_ip}
            },
            'environment': {
                'NUM_PLC': num_plc
            },
            'command': (
                f"sh -c \"{netem_prelude_device} && "  +
                f"apt-get update && apt-get install -y iproute2 && "
                f'ip route del 172.29.0.0/24 && ip route del default && '
                f'ip route add {proxy_ip} dev eth0 &&'
                f'ip route add 172.29.0.0/24 via {proxy_ip} && '
                f'tail -f /dev/null"'
                #f'python3 /scripts/read_coil_requests.py 172.29.0.{i + 121} && tail -f /dev/null"' #measure round trip time of read coil request to a specific PLC 
                #f'python3 /scripts/random_handshake_and_read_coil_requests.py && tail -f /dev/null"' #measure latency(handshake + read coil operation) by contacting random PLC
                #f'python3 /scripts/testing_proxy_availability.py && tail -f /dev/null"'
            )
        }

        compose['services'][proxy_name] = {
            'container_name': proxy_name,
            'build': './proxy',
            'volumes': [f'./volumes/hmi_proxy{i}:/scripts','./volumes/hmi_proxy_shared:/shared_status'],
            'tty': True,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': proxy_ip}
            },
            'environment': {
                'DEVICE_IP': hmi_ip
            },
            
            'command': (
                #f"sh -c \"apt-get update && " +
                #f"apt-get install -y iproute2 && "
                f"sh -c \"{netem_prelude_proxy} &&" +
                f"apt-get update && apt-get install -y iproute2 && "
                + ''.join([
                    f"ip route add 172.29.0.{j + 121} via 172.29.0.{j + 180} && "
                    for j in range(1, num_plc + 1) 
                ])
                + ''.join([
                    f"ip route add 172.29.0.{k + 2} via 172.29.0.{k + 62} && "
                    for k in range(1, num_hmi + 1)  if k != i
                ]) +
                f"cd scripts && " +
                f"pip install ./python-netfilterqueue &&" +
                f"pip install PyJWT && " +
                f"pip install u-msgpack-python && " +
                f"pip install cryptography httpx && " +
                f"chmod +x start_proxy.sh &&" +
                f"exec ./start_proxy.sh\""   
            )
        }

    return compose

def save_compose_file(compose):
    with open('docker-compose.yml', 'w') as file:
        yaml.dump(compose, file, default_flow_style=False)

def main():
    print("Docker Compose Generator")
    num_hmi = int(input("How many HMIs do you want to simulate? "))
    num_plc = int(input("How many PLCs do you want to simulate? "))
    cpus = round(4*(0.27140))
    cm4_ram = "2G"

    create_volume_directories(num_hmi, num_plc)
    compose = generate_compose(num_hmi, num_plc,cpus,cm4_ram)
    save_compose_file(compose)

    print("docker-compose.yml file successfully generated!")

    execute = input("Do you want to execute 'docker-compose up'? (y/n): ").lower()
    if execute == 'y':
        os.system('docker compose up --build -d')  # Run Docker Compose in detached mode
        print("Docker containers are starting...")



        # Execute custom commands inside each PLC container
        for i in range(1, num_plc + 1):
            plc_name = f'plc{i}'
            proxy_ip = f'172.29.0.{i + 180}'
            command = (
                f"docker exec {plc_name} sh -c "
                f"\"ip route del 172.29.0.0/24 && "
                f"ip route del default && "
                f"ip route add {proxy_ip} dev eth0 && "
                f"ip route add 172.29.0.0/24 via {proxy_ip}\""
            )
            print(f"Executing route setup for {plc_name}...")
            os.system(command)
        print("Route setup for PLCs completed.")
        
        time.sleep(5)
        #Starting OpenPLC service
        openplc_service_started = 0
        openplc_login = {
            "username":"openplc",
            "password":"openplc"
        }
        for i in range(1, num_plc + 1):
            openplc_url = f"http://172.29.0.{i + 121}:8080"
            with requests.Session() as session:
                login_response = session.post(f"{openplc_url}/login",data=openplc_login)
                if login_response.status_code == 200:
                    cookies = session.cookies.get_dict()
                    start_response = session.get(f"{openplc_url}/start_plc",cookies=cookies)

                    if start_response.status_code== 200:
                        openplc_service_started += 1

                else:
                    print("Login Error: ",login_response.text)
        
        print(f"OpenPLC's Service Started: {openplc_service_started}")
        
if __name__ == "__main__":
    main()
