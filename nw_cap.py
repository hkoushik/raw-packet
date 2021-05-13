import socket
import textwrap
import eth
import ip
import transport

def multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

TAB1 = "\t"
TAB2 = "\t\t"
TAB3 = "\t\t\t"

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

if __name__ == "__main__":
	while True:
		raw_data, addr = conn.recvfrom(65535)

		dest_mac, src_mac, eth_proto, data = eth.ethernet_unpack(raw_data)
		version, header_len, tos, total_len, identification, x_bit, DFF, MFF, frag_offset, TTL, proto, header_checksum , s_ip, d_ip, data = ip.ip_unpack(data)

		print("Ethernet Frame")
		print(TAB1 + "- Destination Mac : {} , Source Mac : {} , Protocol : {}" .format(str(dest_mac), str(src_mac), str(eth_proto)))

		print(TAB1 + "- IPv4 Packet")
		print("""{}-Version : {}, Header Length : {}, TOS : {}, Total Length : {}
{}- ID : {}, Flags : {}|{}|{}, Fragment Offset : {}, TTL : {}
{}- Protocol : {}, Checksum : {}, Source IP : {}, Destination IP : {}""" .format(TAB2, str(version), str(header_len), str(tos), str(total_len), TAB2, str(identification), str(x_bit), str(DFF), str(MFF), str(frag_offset), str(TTL), TAB2, str(proto), str(header_checksum), str(s_ip), str(d_ip) ))


		if str(proto) == "1":
			icmp_type, icmp_code, icmp_checksum, data = ip.icmp_unpack(data)

			print(TAB2 + "- ICMP Packet")
			print(TAB3 + "- Type : {}, Code : {}, Checksum : {}" .format(str(icmp_type), str(icmp_code), str(icmp_checksum)))
			print(TAB3 + "- Data")
			print(multi_line(TAB3, data))

		elif str(proto) == "6":
			s_port, d_port, seq_no, ack_no, cwr, ece, urg, ack, psh, rst, syn, fin , window, checksum, urg_pointer, data = transport.tcp_unpack(data)
			print(TAB2 + "- TCP Segment")
			print(TAB3 + """- Source Port : {}, Destination Port : {}, SEQ No : {}, ACK No : {}
{}- Flags : {}|{}|{}|{}|{}|{}|{}|{}
{}- Window : {}, Checksum : {}, URG Pointer : {}""" .format( str(s_port), str(d_port), str(seq_no), str(ack_no), TAB3, str(cwr), str(ece), str(urg), str(ack), str(psh), str(rst), str(syn), str(fin), TAB3, str(window), str(checksum), str(urg_pointer) ))
			print(TAB2 + "- Data")
			print(multi_line(TAB3, data))

		elif str(proto) == "17":
			s_port, d_port, length, checksum, data = transport.udp_unpack(data)

			print(TAB2 + "- UDP Datagram")
			print(TAB3 + "- Source Port : {}, Destination Port : {}, Length : {}, Checksum : {}" .format(str(s_port), str(d_port), str(length), str(checksum)))
			print(TAB3 + "- Data")
			print(multi_line(TAB3, data))
