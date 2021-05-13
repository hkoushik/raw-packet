import struct


def tcp_unpack(data):
        s_port, d_port, seq_no, ack_no, offset_reserved, flags, window, checksum, urg_pointer = struct.unpack('! H H L L B B H H H', data[:20])

        offset = offset_reserved >> 4
        reserved = offset & 15

        cwr = (flags >> 7) & 1
        ece = (flags >> 6) & 1
        urg = (flags >> 5) & 1
        ack = (flags >> 4) & 1
        psh = (flags >> 3) & 1
        rst = (flags >> 2) & 1
        syn = (flags >> 1) & 1
        fin = flags  & 1

        return s_port, d_port, seq_no, ack_no, cwr, ece, urg, ack, psh, rst, syn, fin , window, checksum, urg_pointer, data[offset:]

def udp_unpack(data):
        s_port, d_port, length, checksum = struct.unpack('! H H H H', data[:8])
        return s_port, d_port, length, checksum, data[8:]
