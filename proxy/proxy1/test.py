from netfilterqueue import NetfilterQueue
from scapy.all import IP

def process_packet(packet):
    """
    Callback function to process each packet from the NetfilterQueue.
    """
    try:
        # Ottieni il payload del pacchetto
        scapy_packet = IP(packet.get_payload())
        print(f"Packet captured: {scapy_packet.summary()}")
    except Exception as e:
        print(f"Error processing packet: {e}")
    finally:
        # Accetta il pacchetto per non interrompere il flusso
        packet.accept()

def main():
    """
    Main function to bind the NetfilterQueue and start capturing packets.
    """
    queue_num = 0  # Numero della coda NFQUEUE specificata in iptables
    nfqueue = NetfilterQueue()
    
    try:
        print(f"Binding to NFQUEUE {queue_num}...")
        nfqueue.bind(queue_num, process_packet)
        nfqueue.set_queue_maxlen(50000) 
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping NetfilterQueue...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
