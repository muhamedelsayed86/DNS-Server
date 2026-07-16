import socket


def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            packet_id = (1234).to_bytes(2, byteorder='big')    

            flags_int = (1 << 15) 
            flags = flags_int.to_bytes(2, byteorder='big')  

            qdcount = (1).to_bytes(2, byteorder='big') 
            ancount = (0).to_bytes(2, byteorder='big') 
            nscount = (0).to_bytes(2, byteorder='big') 
            arcount = (0).to_bytes(2, byteorder='big')  

            header = packet_id + flags + qdcount + ancount + nscount + arcount

            qname = b"\x0ccodecrafters\x02io\x00"
            qtype = (1).to_bytes(2, byteorder='big')
            qclass = (1).to_bytes(2, byteorder='big')
            
            question_section = qname + qtype + qclass

            response = header + question_section
            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()