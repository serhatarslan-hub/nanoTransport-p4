/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_INFLIGHT_PKTS 10 // Max # of packets that can be in fligth at a time
#define MAX_MSG_LEN_PKTS 100 // Max # of packets that a message can have
#define INDEX_SIZE 14 // Number of bits to index active flows (should be tuned!)
#define MAX_NUM_FLOWS 1 << INDEX_SIZE // Max # of flows NIC can handle

#define INITIAL_TTL 64

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> TYPE_NDP = 0x88F7; // TODO: Determine NDP type indentifier

const bit<16> NDP_FLAG_DATA               = 0x001;
const bit<16> NDP_FLAG_ACK                = 0x002;
const bit<16> NDP_FLAG_PULL               = 0x004;
const bit<16> NDP_FLAG_NACK               = 0x008;
const bit<16> NDP_FLAG_KEEP_ALIVE         = 0x010;
const bit<16> NDP_FLAG_PACER_NUMBER_VALID = 0x020;
const bit<16> NDP_FLAG_FIN                = 0x040;
const bit<16> NDP_FLAG_CHOPPED            = 0x080;
const bit<16> NDP_FLAG_SYN                = 0x100;

typedef bit<MAX_MSG_LEN_PKTS> bitmap_t;

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

header ndp_t {
  bit<16> flags;

  bit<16> checksum;

  bit<32> src_port;
  bit<32> dst_port;

  bit<32> sequence_number;
  /* called "pull_number" for pull segments */

  // bit<32> pacer_number;
  // /* called "pacer_number_echo" for data segments */
  // /* called "recv_window" for ack segments (and maybe nack segments) */
}

/*
 * Segment header is used to send segments (worth of multiple packets) from
 * CPU to NIC
 */
header segment_t { // Context header
  ip4Addr_t srcAddr;
  ip4Addr_t dstAddr;

  bit<32> src_port;
  bit<32> dst_port;

  bit<32> tot_msg_len;
  bit<32> sequence_number;
  bit<16> payload_length;
}

struct headers {
  ethernet_t  ethernet;
  ipv4_t      ipv4;
  ndp_t       ndp;
  segment_t   segment;
} // TODO: Define different header formats

struct metadata {
  // The metadata below is required because source of the
  // correct information may either be the segment header or
  // the IP/NDP headers
  ip4Addr_t srcAddr;
  ip4Addr_t dstAddr;
  bit<32> src_port;
  bit<32> dst_port;

  bit<INDEX_SIZE> flow_indx;
  bit<32> bitmap_indx;
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
      CPU_IN      :parse_segment; //message from CPU -> should be packetized
      PKT_BUF_IN  :parse_ipv4;
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
      TYPE_NDP: parse_ndp;
      default: accept;
    }
  }

  state parse_ndp {
    packet.extract(hdr.ndp);
    transition accept;
  }

  state parse_segment {
    packet.extract(hdr.segment);
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
   * We define some registers below. Since the packetizer, pipeline and the
   * scheduler may need to access some metadata values at the same time, we
   * have different register arrays for them which shall be synchronized on idle
   * clock cycles.
   * Nonetheless, we can define stardard metadata entries instead of the
   * dedicated packetization register array. This standard metadata would be
   * written on the pipeline registers on the corresponding stages where the
   * regular actions write pipeline registers.
   */

  /*
   * Register arrays below are to be synchronized on toBtx_scheduler
   * as a single multi-event register.
   */
  register<bitmap_t>(MAX_NUM_FLOWS) toBtx_packetizer;
  register<bitmap_t>(MAX_NUM_FLOWS) toBtx_pipeline;
  register<bitmap_t>(MAX_NUM_FLOWS) toBtx_scheduler;

  /*
   * Register arrays below are to be synchronized on delvrd_pipeline
   * as a single multi-event register.
   */
  register<bitmap_t>(MAX_NUM_FLOWS) delvrd_packetizer;
  register<bitmap_t>(MAX_NUM_FLOWS) delvrd_pipeline;
  register<bitmap_t>(MAX_NUM_FLOWS) delvrd_scheduler;

  // TODO: There needs to be rtc_cnt register array as well to
  //       cancel transmission after certain number of retries

  /*
   * Register arrays below are to be synchronized on pullOffset_scheduler
   * as a single multi-event register.
   */
  register<bit<32>>(MAX_NUM_FLOWS) pullOffset_packetizer;
  register<bit<32>>(MAX_NUM_FLOWS) pullOffset_pipeline;
  register<bit<32>>(MAX_NUM_FLOWS) pullOffset_scheduler;

  /*
   * Register arrays below are to be synchronized on bitmapHeadSeq_scheduler
   * as a single multi-event register.
   */
  register<bit<32>>(MAX_NUM_FLOWS) bitmapHeadSeq_packetizer;
  register<bit<32>>(MAX_NUM_FLOWS) bitmapHeadSeq_pipeline;
  register<bit<32>>(MAX_NUM_FLOWS) bitmapHeadSeq_scheduler;

  // /*
  //  * Register arrays below are to be synchronized on msgLen_pipeline
  //  * as a single multi-event register.
  //  */
  // register<bit<32>>(MAX_NUM_FLOWS) msgLen_packetizer;
  // register<bit<32>>(MAX_NUM_FLOWS) msgLen_pipeline;

  action set_flow_idx(bit<INDEX_SIZE> flow_indx){
    metadata.flow_idx = flow_idx;
  }

  table get_flow_idx {
    key = {
      metadata.srcAddr: exact;
      metadata.dstAddr: exact;
      metadata.src_port: exact;
      metadata.dst_port: exact;
      // We use 4 tuple instead of 5 because we assume
      // all flows use the same transport protocol anyway
    }
    actions = {
      set_flow_idx;
    }
    default_action = set_flow_idx();
  }

  /*
   * This action, in addition to packetizitation, initiallizes all the
   * metadata (bitmaps and variables etc.). Since this metadata needs to be
   * stored in SRAMs of different stages, we need packetization action to be
   * in this pipeline as well (?)
   */
  action packetize(){
    // TODO:
    //    Divide the segment payload into small packet payloads
    //    Add NDP and IPv4 headers to each packet payload
    //    Store datagrams in the message buffer

    /*    Initiallize all the metadata (bitmaps and variables etc.) */
    toBtx_packetizer.write(metadata.flow_indx, (bit<MAX_MSG_LEN_PKTS>)(-1) ); // all ones
    delvrd_packetizer.write(metadata.flow_indx, 0 ); // all zeros
    pullOffset_packetizer.write(metadata.flow_indx, MAX_MSG_LEN_PKTS);
    bitmapHeadSeq_packetizer.write(metadata.flow_indx, hdr.segment.sequence_number);
    // msgLen_packetizer.write(metadata.flow_indx, hdr.segment.tot_msg_len);
  }

  action get_pkt_idx() {
    bit<32> cur_seq_no = hdr.ndp.sequence_number;

    bit<32> cur_bitmapHeadSeq;
    bitmapHeadSeq_pipeline.read(cur_bitmapHeadSeq, metadata.flow_indx);

    bit<32> cur_idx;
    cur_idx = cur_seq_no - cur_bitmapHeadSeq;
    if (cur_idx >= MAX_MSG_LEN_PKTS){
      // TODO: Here we assume cur_idx can not be greater than 2*MAX_MSG_LEN_PKTS
      cur_idx = cur_idx - MAX_MSG_LEN_PKTS;
    }

    metadata.bitmap_indx = cur_idx;
  }

  /*
   * Scheduler has selected this packet to be transmitted either by looking
   * at the scheduler bitmaps or a timer request.
   */
  action transmit() {

    bitmap_t cur_toBtx;
    @atomic {
      toBtx_pipeline.read(cur_toBtx, metadata.flow_indx);
      cur_toBtx[metadata.cur_idx] = 0;
      toBtx_pipeline.write(metadata.flow_indx, cur_toBtx);
    }

    // TODO: Set a timer for the transmitted cur_seq_no of the flow_idx.
    //       The timer should set the corresponding bitmap entry when expired.
  }

  action ack_rcvd() {

    bitmap_t cur_delvrd;
    @atomic {
      delvrd_pipeline.read(cur_delvrd, metadata.flow_indx);
      cur_delvrd[metadata.cur_idx] = 1;
      delvrd_pipeline.write(metadata.flow_indx, cur_delvrd);
    }

    if (cur_delvrd == (bit<MAX_MSG_LEN_PKTS>)(-1)){ // NOTE: requires special instruction!!
      // TODO: Delete all state regarding that flow
      //       Push the message to the CPU

    } else {
      // TODO: Delete the timer corresponding to this packet!

      // TODO: We can immediately delete the corresponding data packet from the
      //       message buffer. Or we can wait until all delvrd_scheduler bits
      //       are set
    }

  }

  action pull_rcvd(){

    bit<32> cur_pullOffset;
    @atomic {
      pullOffset_pipeline.read(cur_pullOffset, metadata.flow_indx);
      if (hdr.ndp.sequence_number > cur_pullOffset) {
        cur_pullOffset = hdr.ndp.sequence_number;
        pullOffset_pipeline.write(metadata.flow_indx, cur_pullOffset);
      }

    }

  }

  action nack_rcvd() {

    bitmap_t cur_toBtx;
    @atomic {
      toBtx_pipeline.read(cur_toBtx, metadata.flow_indx);
      cur_toBtx[metadata.cur_idx] = 1;
      toBtx_pipeline.write(metadata.flow_indx, cur_toBtx);
    }

    // TODO: Delete the timer corresponding to this packet that was set previously!

  }

  action fin_rcvd() {
    ;
    // TODO: Delete all state regarding that flow if all the packets are
    //       received and push the data to the host.
    //       There might be a state variable to flag if fin is received. Then,
    //       we wouldn't need to check if all the delvrd bitmap bits are set
    //       before this state variable is true.
  }

  action data_rcvd() {

    // TODO: Store the payload into the corresponding message buffer slot

    bitmap_t cur_delvrd;
    @atomic {
      delvrd_pipeline.read(cur_delvrd, metadata.flow_indx);
      cur_delvrd[metadata.cur_idx] = 1;
      delvrd_pipeline.write(metadata.flow_indx, cur_delvrd);
    }

    bit<32> cur_pullOffset;
    @atomic{
      pullOffset_pipeline.read(cur_pullOffset, metadata.flow_indx);
      if (hdr.ndp.sequence_number == cur_pullOffset-MAX_INFLIGHT_PKTS) {
        cur_pullOffset = cur_pullOffset + 1;
        pullOffset_pipeline.write(metadata.flow_indx, cur_pullOffset);
      }
    }

    // Generate an ACK packet back (reverse the incoming packet without payload)
    macAddr_t tempMacAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = tempMacAddr;

    ipv4Addr_t tempIpv4Addr = hdr.ipv4.srcAddr;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = tempIpv4Addr;

    hdr.ipv4.ttl = INITIAL_TTL;
    hdr.ipv4.totalLen = 64;
    // hdr.ipv4.hdrChecksum = recalculate;

    hdr.ndp.flags = NDP_FLAG_ACK;

    standard_metadata.egress_spec = NETWORK_OUT;

    // TODO: Generate a PULL packet and push to the pacer
    sume_gen_pkt(64); // Exemplary extern call for packet generation.
                      // This generated packet will be recirculated, so we can
                      // process it, if need be, before sending out.

    if (cur_delvrd == (bit<MAX_MSG_LEN_PKTS>)(-1)){
      // TODO: Delete all state regarding that flow
      //       Push the message to the CPU

    }
  }

  action chopped_rcvd() {
    macAddr_t tempMacAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = tempMacAddr;

    ipv4Addr_t tempIpv4Addr = hdr.ipv4.srcAddr;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = tempIpv4Addr;

    hdr.ipv4.ttl = INITIAL_TTL;

    hdr.ndp.flags = NDP_FLAG_NACK;

    standard_metadata.egress_spec = NETWORK_OUT;

    // TODO: Generate a PULL packet and push to the pacer
    sume_gen_pkt(64); // Exemplary extern call for packet generation.
                      // This generated packet will be recirculated, so we can
                      // process it before sending out.
  }

  action syn_rcvd() {
    ;
    // TODO: Create new flow entry on get_flow_idx table, and allocate buffer
    //       data and state. (?)
  }

  table packet_handling {
    key = {
      hdr.ndp.flags:  ternary;
      // TODO: Note that a packet may have multiple flags set.
      //       Then it needs to run multiple handle actions.
    }
    actions = {
      ack_rcvd;
      pull_rcvd;
      nack_rcvd;
      // keep_alive_rcvd;
      // pacer_number_valid_rcvd;
      fin_recvd;
      data_rcvd;
      chopped_rcvd;
      syn_rcvd;
      NoAction;
    }
    default_action = NoAction();
  }

  apply {
    if (hdr.ethernet.isValid()) {
      metadata.srcAddr = hdr.ipv4.srcAddr;
      metadata.dstAddr = hdr.ipv4.dstAddr;
      metadata.src_port = hdr. ndp.src_port;
      metadata.dst_port = hdr.ndp.dst_port;

      get_flow_idx.apply();
      if (hdr.ndp.tot_msg_len > MAX_MSG_LEN_PKTS) {
        get_pkt_idx.apply();
      } else {
        metadata.bitmap_indx = hdr.ndp.sequence_number;
      }

      packet_handling.apply();

    } else if (hdr.ipv4.isValid()) {
      standard_metadata.egress_spec = NETWORK_OUT;

      hdr.ethernet.setValid();
      hdr.ethernet.srcAddr = AA:BB:CC:DD:EE:FF; // Set this to be the MAC Addr of the NIC
      hdr.ethernet.dstAddr = 11:22:33:44:55:66; // Set this to be the MAC Addr of the Gateway
      hdr.ethernet.etherType = TYPE_IPV4;

      metadata.srcAddr = hdr.ipv4.srcAddr;
      metadata.dstAddr = hdr.ipv4.dstAddr;
      metadata.src_port = hdr. ndp.src_port;
      metadata.dst_port = hdr.ndp.dst_port;

      get_flow_idx.apply();
      if (hdr.ndp.tot_msg_len > MAX_MSG_LEN_PKTS) {
        get_pkt_idx.apply();
      } else {
        metadata.bitmap_indx = hdr.ndp.sequence_number;
      }

      transmit.apply();

    } else if (hdr.segment.isValid()) {
      metadata.srcAddr = hdr.segment.srcAddr;
      metadata.dstAddr = hdr.segment.dstAddr;
      metadata.src_port = hdr.segment.src_port;
      metadata.dst_port = hdr.segment.dst_port;

      get_flow_idx.apply();
      packetize.apply();

    } else {
      // TODO: Is it safe to assume no unrecognized packet will be received?
    }
  }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

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
    // if (hdr.ethernet.isValid()) {
    //   packet.emit(hdr.ethernet);
    // }
    // packet.emit(hdr.ipv4);
    // packet.emit(hdr.ndp);
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
