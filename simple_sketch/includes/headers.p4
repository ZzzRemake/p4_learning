#ifndef __HEADERS__
#define __HEADERS__

#include "enum.p4"
#include "headers_declaration.p4"

#define CPU_PORT 255

@controller_header("packet_in")
header packet_in_header_t {
    bit<9>  ingress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9>  egress_port;
}

struct headers_t {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
}


// metadata inside switch pipeline
struct metadata_t {
    bit<16> l4_srcPort;
    bit<16> l4_dstPort;
    bit<32> flow_id;
    bit<32> flow_count_val;
    bit<48> last_seen_val;
}


#endif
