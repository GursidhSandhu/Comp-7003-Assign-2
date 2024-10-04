import argparse
from scapy.all import sniff

def hex_to_decimal(hex_string):
    # convert hex to decimal 
    decimal_value = int(hex_string, 16)
    return decimal_value

def hex_to_ip(hex_string):
    # split into pairs, convert to hex and join with .
    # this code was provided by chatgpt
    ip_parts = [str(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]
    return '.'.join(ip_parts)

def hex_to_hardware(hex_string):
    # split into pairs and add :
    hardware_parts = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return ':'.join(hardware_parts)

def hex_to_binary_with_spaces(hex_value):
    # Convert hex to binary and remove the '0b' prefix
    binary_representation = bin(int(hex_value, 16))[2:]
    
    padded_binary = binary_representation.zfill(len(hex_value) * 4)
    # split into sections of 4 bits
    # this code was provided by chatgpt
    spaced_binary = ' '.join(padded_binary[i:i+4] for i in range(0, len(padded_binary), 4))
    
    return spaced_binary

def check_bit(bit):
    # make sure its not a space
    if bit not in ['0', '1']:
        raise ValueError("Input must be a single bit ('0' or '1')")
    return bit

def get_first_three_bits(binary_value):
    binary_value = binary_value.replace(" ", "")
    # get first 3 bits from all the bits
    first_three_bits = binary_value[:3]  
    return first_three_bits

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

    #IPv4
    if(ether_type == '0800'):

        parse_ipv_packet(hex_data)
    
    #ARP
    elif(ether_type == '0806'):

        parse_arp_packet(hex_data)
    
    #should not reach here
    else:
        print(f"Unknown ethertype found: {ether_type}")

def parse_ipv_packet(hex_data):

        #extract all fields
        version = hex_data[28:29]
        ihl = hex_data[29:30]
        tos = hex_data[30:32]
        total_length= hex_data[32:36]
        ip_id = hex_data[36:40]
        offset = hex_data[40:44]
        ttl = hex_data[44:46]
        protocol = hex_data[46:48]
        checksum = hex_data[48:52]
        source_address = hex_data[52:60]
        destination_address = hex_data[60:68]
        packet_endpoint = None
        
        total_length_in_decimal = hex_to_decimal(ihl)
        #check for options
        if(total_length_in_decimal > 40):
            options_bits = total_length_in_decimal - 40
            packet_endpoint = 68 + options_bits
        else:
            packet_endpoint = 68

        #print out all values
        print(f"Version (Hex): {version} -> Human Readable Value: {hex_to_decimal(version)}")
        print(f"Header Length (Hex): {ihl} -> Human Readable Value: {hex_to_decimal(ihl)}")
        print(f"TOS (Hex): {tos} -> Human Readable Value: {hex_to_decimal(tos)}")
        print(f"Total Length (Hex): {total_length} -> Human Readable Value: {hex_to_decimal(total_length)}")
        print(f"IP Identification (Hex): {ip_id} -> Human Readable Value: {hex_to_decimal(ip_id)}")
        print(f"Flags + Offset (Hex): {offset} / {hex_to_binary_with_spaces(offset)} -> Human Readable Value: {hex_to_decimal(offset)}")
        #check flags 
        flags = hex_to_binary_with_spaces(offset)
        three_flag_bits = get_first_three_bits(flags)
        print(f"    - Reserved: {check_bit(three_flag_bits[0])}")
        print(f"    - Don't Fragment: {check_bit(three_flag_bits[1])}")
        print(f"    - More Fragments: {check_bit(three_flag_bits[2])}")
        print(f"    - Offset: 000 / 0 0000 0000 0000")
        print(f"Time To Live (Hex): {ttl} -> Human Readable Value: {hex_to_decimal(ttl)}")
        print(f"Protocol (Hex): {protocol} -> Human Readable Value: {hex_to_decimal(protocol)}")
        print(f"Checksum (Hex): {checksum} -> Human Readable Value: {hex_to_decimal(checksum)}")
        print(f"Source Address (Hex): {source_address} -> Human Readable Value: {hex_to_ip(source_address)}")
        print(f"Destination Address (Hex): {destination_address} -> Human Readable Value: {hex_to_ip(destination_address)}")

        # check if options needs to be printed
        if(packet_endpoint != 68):
            options = hex_data[68:packet_endpoint]
            print(f"Options (Hex): {options}")

        #check for protocol
        protocol_decimal = hex_to_decimal(protocol)
        if(protocol_decimal == 6):
            print('TCP Packet:')
            parse_tcp_packet(hex_data,packet_endpoint)
            
        elif(protocol_decimal == 17):
            print('UDP Packet:')
            parse_udp_packet(hex_data,packet_endpoint)

        # should not reach here
        else:
            print("unknown protocol found")

def parse_tcp_packet(hex_data,packet_endpoint):

            #extract all fields
            source_port = hex_data[packet_endpoint:packet_endpoint + 4]  
            destination_port = hex_data[packet_endpoint + 4:packet_endpoint + 8]  
            sequence_number = hex_data[packet_endpoint + 8:packet_endpoint + 16]  
            ack_number = hex_data[packet_endpoint + 16:packet_endpoint + 24] 
            header_length = hex_data[packet_endpoint + 24:packet_endpoint + 25]  
            reserved = hex_data[packet_endpoint + 25:packet_endpoint + 26]  
            flags = hex_data[packet_endpoint + 26:packet_endpoint + 28]  
            window_size = hex_data[packet_endpoint + 28:packet_endpoint + 32]  
            checksum = hex_data[packet_endpoint + 32:packet_endpoint + 36]  
            urgent_pointer = hex_data[packet_endpoint + 36:packet_endpoint + 40]  
            tcp_options_endpoint = packet_endpoint + 40

            tcp_header_length = hex_to_decimal(header_length)
            #check for options
            if((tcp_header_length * 8) > 40):
                tcp_options_bits = (tcp_header_length * 8) - 40
                tcp_options_endpoint = (packet_endpoint + 40) + tcp_options_bits

            #print fields
            print(f"Source Port (Hex): {source_port} -> Human Readable Value: {hex_to_decimal(source_port)}")
            print(f"Destination Port (Hex): {destination_port} -> Human Readable Value: {hex_to_decimal(destination_port)}")
            print(f"Sequence Number (Hex): {sequence_number} -> Human Readable Value: {hex_to_decimal(sequence_number)}")
            print(f"Acknowledgment Number (Hex): {ack_number} -> Human Readable Value: {hex_to_decimal(ack_number)}")
            print(f"Header Length (Hex): {header_length} -> Human Readable Value: {hex_to_decimal(header_length)}")
            print(f"Reserved (Hex): {reserved} -> Human Readable Value: {hex_to_decimal(reserved)}")
            print(f"Flags (Hex): {flags} / {hex_to_binary_with_spaces(flags)} -> Human Readable Value: {hex_to_decimal(flags)}")
            #check flags
            flag_bits = hex_to_binary_with_spaces(flags)
            print(f"    - CWR: {check_bit(flag_bits[0])}")
            print(f"    - ECE: {check_bit(flag_bits[1])}")
            print(f"    - URG: {check_bit(flag_bits[2])}")
            print(f"    - ACK: {check_bit(flag_bits[3])}")
            # skip the space
            print(f"    - PSH: {check_bit(flag_bits[5])}")
            print(f"    - RES: {check_bit(flag_bits[6])}")
            print(f"    - SYN: {check_bit(flag_bits[7])}")
            print(f"    - FIN: {check_bit(flag_bits[8])}")
            print(f"Window Size (Hex): {window_size} -> Human Readable Value: {hex_to_decimal(window_size)}")
            print(f"Checksum (Hex): {checksum} -> Human Readable Value: {hex_to_decimal(checksum)}")
            print(f"Urgent Pointer (Hex): {urgent_pointer} -> Human Readable Value: {hex_to_decimal(urgent_pointer)}")

            # check if options needs to be printed
            if(tcp_options_endpoint != packet_endpoint + 40):
                options = hex_data[packet_endpoint + 40:tcp_options_endpoint]
                print(f"Options (Hex): {options}")

            #check for data
            data = hex_data[tcp_options_endpoint:]
            if data:
                print(f"Data (Hex): {data}")

def parse_udp_packet(hex_data,packet_endpoint):

            #extract all fields
            source_port = hex_data[packet_endpoint:packet_endpoint + 4]  
            destination_port = hex_data[packet_endpoint + 4:packet_endpoint + 8] 
            length = hex_data[packet_endpoint + 8:packet_endpoint + 12]
            checksum = hex_data[packet_endpoint + 12:packet_endpoint + 16]

            #print fields
            print(f"Source Port (Hex): {source_port} -> Human Readable Value: {hex_to_decimal(source_port)}")
            print(f"Destination Port (Hex): {destination_port} -> Human Readable Value: {hex_to_decimal(destination_port)}")
            print(f"Length (Hex): {length} -> Human Readable Value: {hex_to_decimal(length)}")
            print(f"Checksum (Hex): {checksum} -> Human Readable Value: {hex_to_decimal(checksum)}")

def parse_arp_packet(hex_data):

        #extract all fields
        hardware_address_type = hex_data[28:32]
        protocol_address_type = hex_data[32:36]
        hardware_address_length = hex_data[36:38]
        protocol_address_length = hex_data[38:40]
        opcode = hex_data[40:44]
        source_hardware_address = hex_data[44:56]
        source_protocol_address = hex_data[56:64]
        target_hardware_address = hex_data[64:76]
        target_protocol_address = hex_data[76:84]

        #print out all values
        print(f"Hardware Address Type (Hex): {hardware_address_type} -> Human Readable Value: {hex_to_decimal(hardware_address_type)}")
        print(f"Protocol Address Type (Hex): {protocol_address_type} -> Human Readable Value: {hex_to_decimal(protocol_address_type)}")
        print(f"Hardware Address Length (Hex): {hardware_address_length} -> Human Readable Value: {hex_to_decimal(hardware_address_length)}")
        print(f"Protocol Address Length (Hex): {protocol_address_length} -> Human Readable Value: {hex_to_decimal(protocol_address_length)}")
        print(f"Opcode (Hex): {opcode} -> Human Readable Value: {hex_to_decimal(opcode)}")
        print(f"Source Hardware Address (Hex): {source_hardware_address} -> Human Readable Value: {hex_to_hardware(source_hardware_address)}")
        print(f"Source Protocol Address (Hex): {source_protocol_address} -> Human Readable Value: {hex_to_ip(source_protocol_address)}")
        print(f"Target Hardware Address (Hex): {target_hardware_address} -> Human Readable Value: {hex_to_hardware(target_hardware_address)}")
        print(f"Target Protocol Address (Hex): {target_protocol_address} -> Human Readable Value: {hex_to_ip(target_protocol_address)}")

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)


# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Packet capture program.')
    parser.add_argument('interface', type=str, help='The network interface to capture packets from.')
    
    args = parser.parse_args()
    
    # Call the method once for each protocol
    capture_packets(args.interface, 'ip and tcp', 1)
    capture_packets(args.interface, 'ip and udp', 1)
    capture_packets(args.interface, 'arp', 1)