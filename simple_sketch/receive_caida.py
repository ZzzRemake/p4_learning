#!/usr/bin/env python3
import socket
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class L4Query(Packet):
    name = "L4Query"
    fields_desc = [
        BitField("src_ip", 0, 32), 
        BitField("dst_ip", 0, 32),      # 目的 IP (32-bit)
        BitField("src_port", 0, 16),    # 源端口 (16-bit)
        BitField("dst_port", 0, 16),    # 目的端口 (16-bit)
        BitField("protocol", 0, 8),     # 协议号 (8-bit)
        ByteField("query_type", 0),
        ShortField("query_value", 0),
    ]

bind_layers(IP, L4Query, proto=144)

IPV4_QUERY_PROTO = 144
QUERY_COUNT_PACKET = 0


def ip2num(ip):
    return socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0]) 

def handle_pkt(pkt):
    print("got a packet")
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()

def create_query_pkt(ipv4_src, ipv4_dst, src_ip, dst_ip, src_port, dst_port, protocol, query_type):
    pkt = IP(src_ip=ipv4_src, dst_ip=ipv4_dst) / \
        L4Query(
            src_ip=ip2num(src_ip),
            dst_ip=ip2num(dst_ip),
            dst_port=dst_port,
            src_port=src_port,
            protocol=protocol,
            query_type=query_type,
            query_value=0
        )
    return pkt


def main():
    iface = 'h2-eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
