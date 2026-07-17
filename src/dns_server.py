import socket
import sys

def parse_domain_name(buf, offset):
    labels = []
    while True:
        length = buf[offset]
        if length == 0:
            labels.append(b'\x00')
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            pointer_offset = int.from_bytes(buf[offset:offset+2], 'big') & 0x3FFF
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
    resolver_ip = "8.8.8.8" 
    resolver_port = 53
    if "--resolver" in sys.argv:
        try:
            addr = sys.argv[sys.argv.index("--resolver") + 1]
            resolver_ip, port_str = addr.split(':')
            resolver_port = int(port_str)
        except (ValueError, IndexError):
            print("Usage: --resolver <ip>:<port>")
            sys.exit(1)
        
        
    print(f"Moe tells you server is running on 127.0.0.1:2053")
    print(f"Forwarding queries to {resolver_ip}:{resolver_port}...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_socket.settimeout(2)
    
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
            
            offset = 12
            questions = []
            for _ in range(qdcount_int):
                uncompressed_name, offset = parse_domain_name(buf, offset)
                qtype = buf[offset:offset+2]
                qclass = buf[offset+2:offset+4]
                offset += 4
                questions.append((uncompressed_name, qtype, qclass))
            
            merged_answers = b""
            ans_count = 0
            
            for q in questions:
                uncompressed_name, qtype, qclass = q
                
                f_flags_int = (0 << 15) | (opcode << 11) | (rd << 8) | 0 
                f_flags = f_flags_int.to_bytes(2, 'big')
                f_qdcount = b'\x00\x01'
                f_ancount = b'\x00\x00'
                f_nscount = b'\x00\x00'
                f_arcount = b'\x00\x00'
                
                f_header = packet_id + f_flags + f_qdcount + f_ancount + f_nscount + f_arcount
                f_question = uncompressed_name + qtype + qclass
                
                forward_query = f_header + f_question
                
                forward_socket.sendto(forward_query, (resolver_ip, resolver_port))
                res_buf, _ = forward_socket.recvfrom(1024)
                
                res_ancount = int.from_bytes(res_buf[6:8], 'big')
                
                res_offset = 12
                _, res_offset = parse_domain_name(res_buf, res_offset)
                res_offset += 4 
                
                for _ in range(res_ancount):
                    ans_name, res_offset = parse_domain_name(res_buf, res_offset)
                    ans_type = res_buf[res_offset:res_offset+2]
                    ans_class = res_buf[res_offset+2:res_offset+4]
                    ans_ttl = res_buf[res_offset+4:res_offset+8]
                    
                    ans_rdlength_int = int.from_bytes(res_buf[res_offset+8:res_offset+10], 'big')
                    ans_rdlength = res_buf[res_offset+8:res_offset+10]
                    res_offset += 10
                    
                    ans_rdata = res_buf[res_offset:res_offset+ans_rdlength_int]
                    res_offset += ans_rdlength_int
                    
                    merged_answers += ans_name + ans_type + ans_class + ans_ttl + ans_rdlength + ans_rdata
                    ans_count += 1

            resp_qdcount = qdcount_int.to_bytes(2, 'big')
            resp_ancount = ans_count.to_bytes(2, 'big')
            resp_nscount = (0).to_bytes(2, 'big')
            resp_arcount = (0).to_bytes(2, 'big')

            resp_header = packet_id + flags + resp_qdcount + resp_ancount + resp_nscount + resp_arcount
            resp_questions = b"".join([q[0] + q[1] + q[2] for q in questions])
            
            final_response = resp_header + resp_questions + merged_answers
            udp_socket.sendto(final_response, source)
            
        except Exception as e:
            print(f"[!] Hey! Dropped bad packet : {e}")
            continue

if __name__ == "__main__":
    main()