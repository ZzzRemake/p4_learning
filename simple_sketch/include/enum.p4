#include MAX_PORTS 511

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;
typedef bit<16> l4_port_t;
typedef bit<104> flowID_t;

const bit<9>    CPU_PORT = 255;

// ipv4 service
const bit<8>    PROTO_UDP = 0x11;
const bit<8>    PROTO_TCP = 0x06;
const bit<8>    PROTO_QUERY = 144;

// ethernet
const bit<16>   TYPE_IPV4 = 0x0800;

// query protocol type
const bit<8>    QUERY_COUNT_PACKET = 0x00;