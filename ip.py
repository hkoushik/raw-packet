import struct

def ip_unpack(data):
        vihl, tos, total_len, identification, flags_offset, TTL, proto, header_checksum, s_ip, d_ip = struct.unpack('! B B H H H B B H 4s 4s', data[:20])

        version = vihl>>4
        header_len = vihl & 15

        #Extracting x_bit, Do Not Fragment Flag and More Fragments Follow Flag.
        x_bit =  (flags_offset >> 15) & 1 
        DFF   =  (flags_offset >> 14) & 1
        MFF   =  (flags_offset >> 13) & 1

        #Extracting Fragment Offset
        frag_offset = flags_offset & 8191

        return version, header_len, tos, total_len, identification, x_bit, DFF, MFF, frag_offset, TTL, proto, header_checksum , getip(s_ip), getip(d_ip), data[20:]


def getip(ip_bytes):
        return '.'.join(map(str, ip_bytes))



def icmp_unpack(data):
	icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, icmp_code, icmp_checksum, data[8:]
