import socket

def parse_domain_name(buf, offset):
    labels = []
    while True:
        length = buf[offset]
        
        if length == 0:
            labels.append(b'\x00')
            offset += 1
            break
            
        elif (length & 0xC0) == 0xC0:
            pointer_bytes = buf[offset:offset+2]
            pointer_offset = int.from_bytes(pointer_bytes, 'big') & 0x3FFF
            
            pointed_name, _ = parse_domain_name(buf, pointer_offset)
            labels.append(pointed_name)
            offset += 2
            break
            
        else:
            offset += 1
            labels.append(bytes([length]) + buf[offset:offset+length])
            offset += length
            
    return b''.join(labels), offset

def main():
    print("Moe tells you DNS server is running...")

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

            qdcount_int = int.from_bytes(buf[4:6], 'big')
            
            qdcount = qdcount_int.to_bytes(2, byteorder='big') 
            ancount = qdcount_int.to_bytes(2, byteorder='big') 
            nscount = (0).to_bytes(2, byteorder='big') 
            arcount = (0).to_bytes(2, byteorder='big')  

            header = packet_id + flags + qdcount + ancount + nscount + arcount

            offset = 12
            questions = b""
            answers = b""
            
            for _ in range(qdcount_int):
                uncompressed_name, offset = parse_domain_name(buf, offset)
                
                qtype = buf[offset:offset+2]
                qclass = buf[offset+2:offset+4]
                offset += 4
                
                questions += uncompressed_name + qtype + qclass
                
                atype = (1).to_bytes(2, byteorder='big')
                aclass = (1).to_bytes(2, byteorder='big')
                ttl = (60).to_bytes(4, byteorder='big')          
                rdlength = (4).to_bytes(2, byteorder='big')      
                rdata = b"\x08\x08\x08\x08" # IP : 8.8.8.8
                
                answers += uncompressed_name + atype + aclass + ttl + rdlength + rdata

            response = header + questions + answers
            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()