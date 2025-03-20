/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>    PROTO_UDP = 0x11;
const bit<8>    PROTO_TCP = 0x06;
const bit<8>    PROTO_QUERY = 63;

const bit<16>   TYPE_IPV4 = 0x800;

const bit<8>    QUERY_COUNT_PACKET = 0x00;
// TODO: maybe other query.

const bit<32> FLOW_TABLE_SIZE_EACH = 1024;



#define MAX_HOPS 9
#define HASH_BASE_r1 10w0
#define HASH_BASE_r2 10w0
#define HASH_BASE_r3 10w0
#define HASH_BASE_heavy 10w0

#define HASH_MAX 10w1023
#define HASH_MAX_HEAVY 10w99

#define HASH_SEED_r1 10w12
#define HASH_SEED_r2 10w34
#define HASH_SEED_r3 10w56
#define HASH_SEED_heavy 10w78



/**********************Data structure for CM sketch**********************/
register<bit<32> >(FLOW_TABLE_SIZE_EACH) cms_r1;
register<bit<32> >(FLOW_TABLE_SIZE_EACH) cms_r2;
register<bit<32> >(FLOW_TABLE_SIZE_EACH) cms_r3;



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;
typedef bit<104> flowID_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header query_t {
    flowID_t flowID;
    bit<8>   query_type;
    bit<16>  query_value;
}

struct metadata {
}


struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    tcp_t              tcp;
    udp_t              udp;
}


struct custom_metadata_t {
    // five tuple: FlowId
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

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout custom_metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        //transition parse_ethernet;

        // according to in_port, decie use `parse_ethernet' or `parse_ipv4`
        transition select (standard_metadata.ingress_port) {
            2 : parse_ipv4;
            1 : parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.srcIP = hdr.ipv4.srcAddr;
        meta.dstIP = hdr.ipv4.dstAddr;
        meta.protocol = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP         : parse_
            PROTO_QUERY       : parse_ipv4_option;
            default              : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        metadata.srcPort = hdr.tcp.srcPort;
        metadata.dstPort = hdr.tcp.dstPort;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        metadata.srcPort = hdr.udp.srcPort;
        metadata.dstPort = hdr.udp.dstPort;
        transition accept;
    }

    state parse_query {
        packet.extract(hdr.query);
        metadata.query_flowID = hdr.query.query_flowID;
        metadata.query_type = hdr.query.query_type;
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout custom_metadata_t meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ip_debug {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.protocol: exact;
            hdr.query.count: exact;
            hdr.query.flow_proto: exact;
        }
        actions = {
            NoAction;
        }
        default_action=NoAction();
    }

    action query_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action sketch_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_static {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            query_forward;
            sketch_forward;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        // Do nothing, CAIDA flows have no routing
        // Only process UDP and TCP
        if (hdr.ipv4.protocol != PROTO_UDP && hdr.ipv4.protocol != PROTO_TCP 
                && hdr.ipv4.protocol != PROTO_QUERY) {
            drop();
        } else {
            ip_debug.apply();
            ipv4_static.apply();
        }
    }
}



/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout custom_metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    // a fake table for cms table debug in bmv2
    table cms_debug{
        key = {
            meta.ha_r1: exact;
            meta.ha_r2: exact;
            meta.ha_r3: exact;

            meta.qc_r1: exact;
            meta.qc_r2: exact;
            meta.qc_r3: exact;
            meta.cms_freq_estimate: exact;

            meta.my_flowID: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    // a debug table for count query
    table count_query_debug {
        key = {
            meta.freq_estimate: exact;
            hdr.query.count: exact;
            hdr.query.flow_proto: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    // joint the five tuples into FlowID
    // 五元组在哪我请问了
    action compute_flow_id () {
        meta.my_flowID[31:0] = hdr.ipv4.srcAddr;
        meta.my_flowID[63:32] = hdr.ipv4.dstAddr;
        meta.my_flowID[79:64] = meta.srcPort;
        meta.my_flowID[95:80] = meta.dstPort;
        meta.my_flowID[103:96]=hdr.ipv4.protocol;

        meta.my_flow_cnt = 32w1;
    }

    // get the hash bucket in each row 
    action compute_reg_index() {
        hash(meta.ha_r1, HashAlgorithm.crc16, HASH_BASE_r1,
                {meta.my_flowID, HASH_SEED_r1}, HASH_MAX);
        hash(meta.ha_r2, HashAlgorithm.crc16, HASH_BASE_r2,
                {meta.my_flowID, HASH_SEED_r2}, HASH_MAX);
        hash(meta.ha_r3, HashAlgorithm.crc16, HASH_BASE_r3,
                {meta.my_flowID, HASH_SEED_r3}, HASH_MAX);
    }

    action min_cnt(inout bit<32> mincnt, in bit<32> cnt1, in bit<32> cnt2,
                    in bit<32> cnt3) {
        if(cnt1 < cnt2) {
            mincnt = cnt1;
        } else {
            mincnt = cnt2;
        }

        if(mincnt > cnt3) {
            mincnt = cnt3;
        }
    }

    apply {
        if (hdr.ipv4.protocol != PROTO_QUERY){
            compute_flow_id();
            compute_reg_index(); // need flowid
            cms_r1.read(meta.qc_r1, meta.ha_r1);
            cms_r2.read(meta.qc_r2, meta.ha_r2);
            cms_r3.read(meta.qc_r3, meta.ha_r3);

            min_cnt(meta.cms_freq_estimate, meta.qc_r1, meta.qc_r2, meta.qc_r3);

            // update cfb
            cms_r1.write(meta.ha_r1, meta.qc_r1 + meta.my_flow_cnt);
            cms_r2.write(meta.ha_r2, meta.qc_r2 + meta.my_flow_cnt);
            cms_r3.write(meta.ha_r3, meta.qc_r3 + meta.my_flow_cnt);

            // for debug, reload sketch to meta
            cms_r1.read(meta.qc_r1, meta.ha_r1);
            cms_r2.read(meta.qc_r2, meta.ha_r2);
            cms_r3.read(meta.qc_r3, meta.ha_r3);

            min_cnt(meta.cms_freq_estimate, meta.qc_r1, meta.qc_r2, meta.qc_r3);
            cms_debug.apply();
        } // end insertion in CountMin Sketch
        else {
            if (hdr.query.query_type == QUERY_COUNT_PACKET) {
                compute_reg_index(); // need flowid
                cms_r1.read(meta.qc_r1, meta.ha_r1);
                cms_r2.read(meta.qc_r2, meta.ha_r2);
                cms_r3.read(meta.qc_r3, meta.ha_r3);

                min_cnt(meta.freq_estimate, meta.qc_r1, meta.qc_r2, meta.qc_r3);
                hdr.query.count = (bit<16>)meta.freq_estimate;
                count_query_debug.apply();                
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout custom_metadata_t meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            {   hdr.ipv4.version,
	            hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.query);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
