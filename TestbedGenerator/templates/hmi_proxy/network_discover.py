import socket
import time 

BROADCAST_IP = "255.255.255.255"
PORT = 7000
MESSAGE = b"Hello"
MAX_ATTEMPTS = 5
REQUIRED_RESPONSES = 3
TIMEOUT = 3
OUTPUT_FILE = "peers.txt"


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
    with open(OUTPUT_FILE, "w") as f:
        for response in responses:
            f.write(f"{response[0]} {response[1]}\n")  
            
            
def send_broadcast_message():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SQL_SOCKET, socket.SO_BROADCAST,1)
    s.settimeout(TIMEOUT)
    
    peers = set()
    attempts = 0
    
    try:
        while attempts < MAX_ATTEMPTS:
            s.sendto(MESSAGE, (BROADCAST_IP, PORT))
            start_time = time.time()
            while time.time() - start_time < TIMEOUT:
                try:
                    response, addr = s.recvfrom(1024)
                    response_text = response.decode().strip()
                    
                    if response_text:
                        peer_info = tuple(response_text.split(":"))
                        response_tuple = (peer_info[0],int(peer_info[1]))
                        
                        if response_tuple not in peers:
                            peers.add(response_tuple)
                            
                    if len(peers) >= REQUIRED_RESPONSES:
                        save_responses(peers)
                        return
                    
                except s.timeout:
                    break
                
            attempts +=1
            time.sleep(2)
        
        save_responses(peers)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        
        
if __name__ == "__main__":
    send_broadcast_message()
        