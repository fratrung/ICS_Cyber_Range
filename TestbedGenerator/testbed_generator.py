import os
import yaml

def create_volume_directories(num_hmi, num_plc):
    hmi_template = "templates/hmi_proxy"
    plc_template = "templates/plc_proxy"

    #flush volimes direcory
    if os.path.exists('volumes'):
        os.system('rm -r volumes')
    
    os.makedirs('volumes')

    for i in range(1, num_hmi + 1):
        os.system(f'cp -rf {hmi_template} volumes/hmi_proxy{i}')
    for i in range(1, num_plc + 1):
        os.system(f'cp -rf {plc_template} volumes/plc_proxy{i}')

def generate_compose(num_hmi, num_plc):
    compose = {
        'version': '3.9',
        'services': {
            'central-server': {
                'build': './server',
                'ports': ['5000:5000'],
                'networks': {
                    'network1': {
                        'ipv4_address': '172.29.0.2'
                    }
                }
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
        }
    }

    # Add PLC services and proxies
    for i in range(1, num_plc + 1):
        plc_name = f'plc{i}'
        proxy_name = f'plc_proxy{i}'

        plc_ip = f'172.29.0.{i + 50}'
        proxy_ip = f'172.29.0.{i + 100}'

        compose['services'][plc_name] = {
            'container_name': plc_name,
            'build': f'./plc/plc1',
            'ports': [f"808{i}:8080"],
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': plc_ip}
            }
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
                f"sh -c \"apt-get update && " +
                f"apt-get install -y iproute2 && "
                + ''.join([
                    f"ip route add 172.29.0.{j + 50} via 172.29.0.{j + 100} && "
                    for j in range(1, num_plc + 1)  if j != i
                ])
                + ''.join([
                    f"ip route add 172.29.0.{k + 4} via 172.29.0.{k + 7} && "
                    for k in range(1, num_hmi + 1) 
                ]) +
                f"cd scripts && " +
                f"pip install ./python-netfilterqueue &&" +
                f"tail -f /dev/null\""
            )
        }

    # Add HMI services and proxies
    for i in range(1, num_hmi + 1):
        hmi_name = f'hmi{i}'
        proxy_name = f'hmi_proxy{i}'

        hmi_ip = f'172.29.0.{i + 4}'
        proxy_ip = f'172.29.0.{i + 7}'

        # Determine corresponding PLC proxy
        plc_proxy_ip = f'172.29.0.{i + 100}' if i <= num_plc else ""
        plc_ip = f'172.29.0.{i + 50}' if i <= num_plc else ""

        compose['services'][hmi_name] = {
            'container_name': hmi_name,
            'build': './hmi',
            'volumes': ['./hmi/scripts:/scripts'],
            'tty': True,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': hmi_ip}
            },
            'command': (
                f'sh -c "apt-get update && '
                f'apt-get install -y iproute2 && '
                f'ip route del 172.29.0.0/24 && ip route del default && '
                f'ip route add {proxy_ip} dev eth0 &&'
                f'ip route add 172.29.0.0/24 via {proxy_ip} && '
                f'tail -f /dev/null"'
            )
        }

        compose['services'][proxy_name] = {
            'container_name': proxy_name,
            'build': './proxy',
            'volumes': [f'./volumes/hmi_proxy{i}:/scripts'],
            'tty': True,
            'cap_add': ['NET_ADMIN'],
            'networks': {
                'network1': {'ipv4_address': proxy_ip}
            },
            'environment': {
                'DEVICE_IP': hmi_ip
            },
            'command': (
                f"sh -c \"apt-get update && " +
                f"apt-get install -y iproute2 && "
                + ''.join([
                    f"ip route add 172.29.0.{j + 50} via 172.29.0.{j + 100} && "
                    for j in range(1, num_plc + 1) 
                ])
                + ''.join([
                    f"ip route add 172.29.0.{k + 4} via 172.29.0.{k + 7} && "
                    for k in range(1, num_hmi + 1)  if k != i
                ]) +
                f"cd scripts && " +
                f"pip install ./python-netfilterqueue &&" +
                f"tail -f /dev/null\""
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

    create_volume_directories(num_hmi, num_plc)
    compose = generate_compose(num_hmi, num_plc)
    save_compose_file(compose)

    print("docker-compose.yml file successfully generated!")

    execute = input("Do you want to execute 'docker-compose up'? (y/n): ").lower()
    if execute == 'y':
        os.system('docker compose up -d')  # Run Docker Compose in detached mode
        print("Docker containers are starting...")

        # Execute custom commands inside each PLC container
        for i in range(1, num_plc + 1):
            plc_name = f'plc{i}'
            proxy_ip = f'172.29.0.{i + 100}'
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
if __name__ == "__main__":
    main()
