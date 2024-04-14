// P4 code for a simple intrusion detection system (IDS) in the data plane

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define FLOW_ENTRIES 4096
#define PATTERN_WIDTH 32

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header payload_t {
    bit<PATTERN_WIDTH> data;
}

struct metadata {
    // empty
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    payload_t    payload;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IDS_Parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        //check etherType
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4; //if etherType is ipv4 -> go to state ipv4
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        //check protocol in ipv4 header
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp; //if procotol is tcp -> go to state tcp
            default: accept;
        }     
    }

    state tcp {
        //extract the tcp header for ports
        packet.extract(hdr.tcp);
        transition payload; //go to state payload
    }

    state payload {
        packet.extract(hdr.payload); //extract payload
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control IDS_VerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IDS_Ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(FLOW_ENTRIES) counters; //number of packet dropped per flow
    register<bit<1>>(FLOW_ENTRIES) blocked_flows; 
    bit<1> current_flow; //bit to check status of current flow
    bit<PATTERN_WIDTH> hashed_int; // get hashed result from crc32

    action increment_counter() {
        bit<PATTERN_WIDTH> temp;
        hash(hashed_int, HashAlgorithm.crc32, (bit<16>)0
        , {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}
        , (bit<32>)FLOW_ENTRIES);

        counters.read(temp, hashed_int);
        temp = temp + 1;
        counters.write(hashed_int, temp);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action signature_hit(bit<9> egress_port) {
        //When a pattern is found in the packet
        standard_metadata.egress_spec = egress_port;

        bit<PATTERN_WIDTH> temp;
        hash(hashed_int, HashAlgorithm.crc32, (bit<16>)0
        , {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}
        , (bit<32>)FLOW_ENTRIES);


        counters.read(temp, hashed_int);
        temp = temp + 1;
        counters.write(hashed_int, temp);

        blocked_flows.write(hashed_int, 1);
        current_flow = 1;
    }

    action get_flow_status() {
        //Calculate the index in register array corresponding to this flow
        //Read from a register whether the flow is blocked
        hash(hashed_int, HashAlgorithm.crc32, (bit<16>)0
        , {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}
        , (bit<32>)FLOW_ENTRIES);

        blocked_flows.read(current_flow, hashed_int);
    }

    // `flows` is a keyless table used to execute a single action: get_flow_status().
    table flows {
        actions = {
            get_flow_status;
        }

        size = 1;
        default_action = get_flow_status();
    }

    table signatures {
         key = {
            hdr.payload.data: exact;
        }

        actions = {
            signature_hit;
            NoAction;
        }

        size = 512;
        default_action = NoAction();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //set the src mac address as the previous dst
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            //get flow status
            flows.apply();
            //check if flow isn't blocked
            if (current_flow == 0)
                if (signatures.apply().miss)//if signatures apply miss -> perform ipv4 forwarding
                    ipv4_lpm.apply();
            else
                increment_counter(); //increment number of dropped packets
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IDS_Egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control IDS_ComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
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

control IDS_Deparser(packet_out packet, in headers hdr) {
    apply {
        // Parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

// Switch architecture
V1Switch(
IDS_Parser(),
IDS_VerifyChecksum(),
IDS_Ingress(),
IDS_Egress(),
IDS_ComputeChecksum(),
IDS_Deparser()
) main;