#ifndef __HEADERS__
#define __HEADERS__

#include "enum.p4"

// packet-in (send-to-controller)
@controller_header("packet_in")
header packet_in_header_t {
    bit<9>  ingress_port;
    bit<104> flowID; 
    bit<7>  _padding;
}

// packet-out (send-from-controller)
@controller_header("packet_out")
header packet_out_header_t {
    bit<9>  egress_port;
    bit<7>  _padding;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// standard tcp
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset; // how long the TCP header is
    bit<3>  res;
    bit<3>  ecn; //Explicit congestion notification
    bit<6>  ctrl; // URG,ACK,PSH,RST,SYN,FIN
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

header query_t {
    flowID_t flowID;
    bit<8>   query_type;
    bit<16>  query_value;
}

struct headers {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
    query_t             query;
}


struct custom_metadata_t {
    ip4Addr_t srcIP;
    ip4Addr_t dstIP;
    port_t   srcPort;
    port_t   dstPort;
    bit<8>    protocol;

    // sketch used.
    flowID_t my_flowID;
    bit<32>  my_flow_cnt;

    flowID_t query_flowID;
    bit<8> query_type;

    // hash address in row 1
    bit<32> ha_r1;
    // hash address in row 2
    bit<32> ha_r2;
    // hash address in row 3
    bit<32> ha_r3;

    // query count in row 1
    bit<32> qc_r1;
    // query count in row 2
    bit<32> qc_r2;
    // query count in row 3
    bit<32> qc_r3;

    bit<32> freq_estimate;
    bit<32> cms_freq_estimate;
}


#endif