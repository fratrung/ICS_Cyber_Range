import socket
import time 




def load_peers(filename="peers.txt"):
    peers = []
    try:
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) == 2: 
                    ip, port = parts[0], int(parts[1])
                    peers.append((ip, port))  

    except FileNotFoundError:
        print(f"[!] The file '{filename}' does not exists. No peer in the network")
        return peers
    except Exception as e:
        print(f"[X] Errore durante la lettura del file: {e}")

    return peers


def save_responses(responses):
    print("Salvo le risposte")
    with open("peers.txt", "w") as f:
        for response in responses:
            f.write(f"{response[0]} {response[1]}\n")  
            
            
def send_broadcast_message():
    print("Sending Broadcast message for DHT's Peers discovery..")
    BROADCAST_IP = "172.29.0.255"
    PORT = 7000
    MESSAGE = b"Hello"
    MAX_ATTEMPTS = 5
    REQUIRED_RESPONSES = 3
    TIMEOUT = 3
    OUTPUT_FILE = "peers.txt"
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    s.settimeout(TIMEOUT)
    
    peers = set()
    attempts = 0
    
    try:
        while attempts < MAX_ATTEMPTS:
            #print(f"{attempts} attempts")
            s.sendto(MESSAGE, (BROADCAST_IP, PORT))
            start_time = time.time()
            while time.time() - start_time < TIMEOUT:
                try:
                    response, addr = s.recvfrom(1024)
                    response_text = response.decode().strip()
                    
                    if response_text:
                        
                        peer_info = tuple(response_text.split(":"))
                        response_tuple = (peer_info[0],int(peer_info[1]))
                        print(f"Response received --> {response_tuple}")
                        
                        if response_tuple not in peers:
                            print(f"Response received --> {response_tuple}")
                            peers.add(response_tuple)
                            
                    if len(peers) >= REQUIRED_RESPONSES:
                        save_responses(peers)
                        return peers
                    
                except socket.timeout:
                    #print("tempo di attesa terminato, nuovo tentativo.")
                    break
                
            attempts +=1
            time.sleep(2)
        
        save_responses(peers)
        return peers
        
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        

        
