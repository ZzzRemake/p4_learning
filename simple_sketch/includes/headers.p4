/**
    Layer 2 protocol
*/

// standard ethernet 
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// 802.1 Q (ethernet with VLAN)
header vlan_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> tpid;       // tag protocol identifier
    bit<3>  pcp;        // priority code point 
    bit<1>  dei;        // drop eligible indicator
    bit<12> vid;        // VLAN identifier
    // pcp + dei + vid = tci , Tag control information
    bit<16> etherType;
}

/**
    Layer 3 protocol (including Layer 2.5 )
*/

// ARP IP protocol 
header arp_t {
    bit<8>  htype;      // HW type
    bit<8>  ptype;      // Protocol type
    bit<4>  hlen;       // HW addr len
    bit<4>  oper;       // Proto addr len
    bit<48> srcMacAddr; // source mac addr
    bit<32> srcIPAddr;  // source IP addr
    bit<48> dstMacAddr; // destination mac addr
    bit<32> dstIPAddr;  // destination IP addr
}

// ICMP - timestamp request/response
header icmp_ts_t {
    bit<8> type;
    bit<8> code;
    bit<16> hdrChecksum;
    bit<16> identifier;
    bit<16> seqNum;
    bit<32> originTs;       // originate timestamp
    bit<32> recvTs;         // receive timestamp
    bit<32> tranTs;         // transmit timestamp
}

// ICMP 
header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> hdrChecksum;
    bit<16> empty;
    bit<16> nextHopMtu;
    // FIXME:
    // Need to include "IP Header"
    // And First 8 bytes of Original Datagram's Data
    // ipv4_t ipv4;
    // bit<64> originData; 
}

// standard ipv4
// transition select    - protocol
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
}

// standard ipv6
// transition select    - nextHeader
header ipv6_t {
    bit<4>      version;
    bit<8>      trafficClass;
    bit<20>     flowlabel;
    bit<16>     payloadLen;
    bit<8>      nextHeader;
    bit<8>      hopLimit;
    bit<128>    srcAddr;
    bit<128>    dstAddr;
}

/**
    Layer 4 protocol
*/

// standard tcp
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// standard udp
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// VXLAN support 
header vxlan_t {
    bit<8>  vxflags;
    bit<24> rsvd1;      // reserved
    bit<24> vnid;       // identifier
    bit<8>  rsvd2;      // reserved
}


