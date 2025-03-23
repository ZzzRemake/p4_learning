#ifndef __BLOOM_FILTER__
#define __BLOOM_FILTER__

#include <core.p4>
#include <v1model.p4>

const bit<32> BLOOM_FILTER_SIZE = 10240

#define BLOOM_HASH_SEED1 10w11
#define BLOOM_HASH_SEED2 10w45
#define BLOOM_HASH_SEED3 10w14
#define BLOOM_HASH_SEED4 10w19
#define BLOOM_HASH_BASE  10w00

register<bit<1> >(BLOOM_FILTER_SIZE) bloom_filter;

control BloomFilterQuery(in bit<104> flowID,
                         inout bool is_exist) {
    table bloom_query_debug {
        key = {
            flowID: exact;
            is_exist: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }
    apply {
        bit<32> hash_index_1;
        bit<32> hash_index_2;
        bit<32> hash_index_3;
        bit<32> hash_index_4;

        bit<1> hash_v1;
        bit<1> hash_v2;
        bit<1> hash_v3;
        bit<1> hash_v4;

        hash(hash_index_1, HashAlgorithm.crc16, BLOOM_HASH_BASE,
            {flowID, BLOOM_HASH_SEED1}, BLOOM_FILTER_SIZE);
        hash(hash_index_2, HashAlgorithm.crc16, BLOOM_HASH_BASE,
            {flowID, BLOOM_HASH_SEED2}, BLOOM_FILTER_SIZE);
        hash(hash_index_3, HashAlgorithm.crc16, BLOOM_HASH_BASE,
            {flowID, BLOOM_HASH_SEED3}, BLOOM_FILTER_SIZE);
        hash(hash_index_4, HashAlgorithm.crc16, BLOOM_HASH_BASE,
            {flowID, BLOOM_HASH_SEED4}, BLOOM_FILTER_SIZE);
        
        bloom_filter.read(hash_v1, hash_index_1);
        bloom_filter.read(hash_v2, hash_index_2);
        bloom_filter.read(hash_v3, hash_index_3);
        bloom_filter.read(hash_v4, hash_index_4);

        is_exist = (hash_v1 == 1 && hash_v2 == 1 && hash_v3 == 1 && hash_v4 == 1) ;
    }
}

#endif