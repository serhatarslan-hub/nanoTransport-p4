/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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

header homa_t {

    // bit<16> srcPort;
    // bit<16> dstPort;
    bit<16> rpcID;

    /* Type: DATA, GRANT, RESEND, BUSY */
    bit<2>  type;

    /* Incast factor to reduce amount of unscheduled Packes */
    bit<1>  incast;

    /* Size of granted/resent portion of message if type is not DATA
     * Size of whole message if type is DATA */
    bit<5>  length;

    /* Offset of granted/resent portion of message */
    bit<32> offset;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    homa_t      homa;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port){
          NETWORK_IN  :parse_ethernet;
          CPU_IN      :parse_ipv4; //message from CPU -> should be packetized
          deafult     :accept;
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
        transition select(hdr.ipv4.protocol){
            TYPE_HOMA: parse_homa;
            default: accept;
        }
    }

    state parse_homa {
        packet.extract(hdr.homa);
        transition accept;
    }
}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /*
    * Creates a new state entry on new messages.
    * Calls enqueue_rpc action.
    */
    action create_rpc_record() {
        // TODO:
        //    <Ptr> new_rpc = new RPC();
        //    enqueue_rpc(new_rpc);
    }

    /*
    * Table returns a pointer to the matched RPC.
    * Packetizes the message and adds the packets to the pointed queue.
    * Depending on the message length, priority is set on IP header.
    */
    action enqueue_rpc(<Ptr> rpc) {
        // TODO:
        //    decide on sending priority, put it on IP header
        //    packetize, add ethernet headers, set proper hdr.homa.offset values
        //    enqueue to pkt_list of the RPC
    }

    table egress_messages {
        key = {
            hdr.homa.rpcID:  exact;
        }
        actions = {
            enqueue_rpc;
            create_rpc_record;
        }
        default_action = create_rpc_record();
    }

    action data_rcvd() {
        standard_metadata.egress_spec = CPU_OUT;
        // TODO:
        //    update message length stats for priority determination
        //    hdr.ethernet.setInvalid();
        //    if new rpc
        //        <Ptr> new_rpc = new RPC();
        //    put the data in pkt_list of the rpc
        //    set rpcID.priority;
        //    increase rpcID.rcvd_offset of the rpc
        //    if hdr.homa.incast != 1
        //        rpcID.grnt_offset = rpcID.rcvd_offset + RTTbytes;
        //    else
        //        rpcID.grnt_offset = rpcID.rcvd_offset + RTTbytes/incast_factor;
        //    if message is completed
        //        consolidate packets into a message
        //        send the message to CPU
        //        clear rpc state
        //    else
        //        trigger a GRANT transmission
        //    clear timers
    }

    action grnt_rcvd() {
        // TODO:
        //    rpcID.grnt_offset = hdr.homa.offset + hdr.homa.length;
        //    rpcID.rcvd_offset = hdr.homa.offset;
        //    rpcID.prio = hdr.ipv4.diffserv[x:y];
        //    clear rpc queue until rpcID.rcvd_offset
        //    if will not be able to unschedule
        //        trigger a BUSY transmission
    }

    action rsnd_rcvd() {
        // TODO:
        //    rpcID.rcvd_offset = hdr.homa.offset;
        //    rpcID.prio = hdr.ipv4.diffserv[x:y];
    }

    action busy_rcvd() {
        // TODO:
        //    extend/stop/reset the sending timers of the corresponding rpcID
    }

    table ingress_messages {
        key = {
            hdr.homa.type:  exact;
        }
        actions = {
            data_rcvd;
            grnt_rcvd;
            rsnd_rcvd;
            busy_rcvd;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            ingress_messages.apply();
        } else {
            standard_metadata.egress_spec = NETWORK_OUT;
            egress_messages.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action data_snd() {
        // TODO:
        //    hdr.ipv4.diffserv[x:y] = rpcID.prio;
        //    set a timer for rpcID.rcvd_offset
    }

    action grnt_snd() {
        // TODO:
        //    set timer for rpcID.rcvd_offset
    }

    action rsnd_snd() {
        // TODO:
        //    reset timer for rpcID.rcvd_offset
    }

    table egress_messages {
      key = {
          hdr.homa.type:  exact;
      }
      actions = {
          data_snd;
          grnt_snd;
          rsnd_snd;
          NoAction;
      }
      default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            egress_messages.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {

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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        if (hdr.ethernet.isValid()) {
            packet.emit(hdr.ethernet);
        }
        packet.emit(hdr.ipv4);
        packet.emit(hdr.homa);
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
