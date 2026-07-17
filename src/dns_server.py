import socket

def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            packet_id = buf[:2]
            opcode = (buf[2] & 0b01111000) >> 3
            rd = buf[2] & 0b00000001
            rcode = 0 if opcode == 0 else 4

            flags_int = (1 << 15) | (opcode << 11) | (rd << 8) | rcode 
            flags = flags_int.to_bytes(2, byteorder='big')  

            qdcount = (1).to_bytes(2, byteorder='big') 
            ancount = (1).to_bytes(2, byteorder='big') 
            nscount = (0).to_bytes(2, byteorder='big') 
            arcount = (0).to_bytes(2, byteorder='big')  

            header = packet_id + flags + qdcount + ancount + nscount + arcount

            null_byte_index = buf.find(b'\x00', 12)
            
            qname = buf[12:null_byte_index + 1]
            
            question_section = buf[12:null_byte_index + 5]

            aname = qname 
            
            atype = (1).to_bytes(2, byteorder='big')
            aclass = (1).to_bytes(2, byteorder='big')
            ttl = (60).to_bytes(4, byteorder='big')          
            rdlength = (4).to_bytes(2, byteorder='big')      
            rdata = b"\x08\x08\x08\x08"

            answer_section = aname + atype + aclass + ttl + rdlength + rdata

            response = header + question_section + answer_section
            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()