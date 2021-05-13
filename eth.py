import struct
import socket

def ethernet_unpack(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return getmac(dest_mac), getmac(src_mac), socket.htons(eth_proto), data[14:]


def getmac(mac_bytes):
    mac = map ('{:02x}'.format, mac_bytes)
    return (':'.join(mac)).upper()
