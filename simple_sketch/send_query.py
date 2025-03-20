#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField, LongField, ByteField, BitField
from scapy.layers.inet import _IPOption_HDR

from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
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


def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <source> <destination>')
        exit(1)

    src_addr = socket.gethostbyname(sys.argv[1])
    addr = socket.gethostbyname(sys.argv[2])
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
        IP(src_ip=src_addr, dst_ip=addr) / \
        L4Query(
            src_ip=ip2num("src_ip"),
            dst_ip=ip2num("dst_ip"),
            dst_port="dst_port",
            src_port="src_port",
            protocol=IPV4_QUERY_PROTO,
            query_type=QUERY_COUNT_PACKET,
            query_value=0
        )

 #   pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 #       dst=addr, options = IPOption_MRI(count=2,
 #           swtraces=[SwitchTrace(swid=0,qdepth=0), SwitchTrace(swid=1,qdepth=0)])) / UDP(
 #           dport=4321, sport=1234) / sys.argv[2]
    pkt.show2()
    #hexdump(pkt)
    # try:
    #   for i in range(int(sys.argv[4])):
    #     sendp(pkt, iface=iface)
    #     sleep(1)
    # except KeyboardInterrupt:
    #     raise
    try:
        sendp(pkt, iface=iface)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
