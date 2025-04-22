#include <core.p4>
#include <v1model.p4>

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action replicate() {
        standard_metadata.mcast_grp = 10;
    }

    table check_replicate {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            replicate;
            NoAction;
        }
        size = 1024;
        default_action = replicate();
    }

    apply {
        if (hdr.ethernet.isValid())
            check_replicate.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        // Prune multicast packet to ingress port to prevent loop
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            mark_to_drop(standard_metadata);
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
